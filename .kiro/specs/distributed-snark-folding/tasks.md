# Implementation Plan: Distributed SNARK via Folding Schemes

This implementation plan breaks down the distributed SNARK system into discrete, manageable coding tasks. Each task builds incrementally on previous tasks, with all code integrated into the system. Tasks are organized by implementation phases, with core functionality prioritized and optional testing tasks marked with *.

## Phase 1: Core Cryptographic Primitives Foundation

- [ ] 1. Set up project structure and core interfaces
  - Create Rust workspace with cargo.toml dependencies (ark_ff, ark_ec, ark_poly, ark_bn254, ark_serialize, rayon)
  - Define core trait interfaces for Field, Group, Polynomial operations
  - Set up module structure: primitives/, protocols/, network/, utils/
  - Configure BN254 curve parameters and security constants (λ=128)
  - _Requirements: 1.1, 22.1-22.7, 34.1-34.2_

- [ ] 2. Implement field arithmetic module
  - [ ] 2.1 Implement FieldElement wrapper with BN254 scalar field
    - Wrap ark_ff::Field with custom FieldElement<F> type
    - Implement arithmetic operations: add, sub, mul, div, inv, pow
    - Implement Montgomery representation for efficient modular arithmetic
    - Handle edge cases: division by zero, field element validation
    - _Requirements: 1.1, 38.1-38.8_
  
  - [ ] 2.2 Implement batch inversion using Montgomery's trick
    - Create batch_inverse function taking &[F] and returning Vec<F>
    - Implement forward pass computing cumulative products
    - Implement backward pass computing individual inverses
    - Optimize to O(n) multiplications + 1 inversion
    - _Requirements: 1.1, 19.3, 38.7_
  
  - [ ] 2.3 Implement field element serialization
    - Serialize field elements in ⌈log₂|F|⌉ bits (32 bytes for BN254)
    - Use little-endian encoding for consistency
    - Implement validation on deserialization (check element in range [0,p))
    - _Requirements: 33.1, 33.6_

- [ ] 3. Implement elliptic curve operations module
  - [ ] 3.1 Implement GroupElement wrapper for BN254 G1/G2
    - Wrap ark_ec::Group with custom GroupElement<G> type
    - Implement point addition, doubling, scalar multiplication
    - Support both G1 (256-bit) and G2 (512-bit) points
    - _Requirements: 1.1, 39.1-39.3_
  
  - [ ] 3.2 Implement multi-scalar multiplication using Pippenger's algorithm
    - Create msm function taking scalars &[BigUint] and points &[G]
    - Implement bucket method with window size w=8
    - Optimize for typical sizes (M ∈ {2,4,8} provers)
    - Achieve O(M/log M · log p) complexity
    - _Requirements: 1.1, 19.7, 39.4_
  
  - [ ] 3.3 Implement point compression and pairing
    - Compress points using x-coordinate + sign bit (33 bytes G1, 65 bytes G2)
    - Implement decompression with curve validation
    - Implement optimal ate pairing for BN254: e(P,Q)
    - _Requirements: 1.1, 33.2, 39.5-39.7_


- [ ] 4. Implement polynomial operations module
  - [ ] 4.1 Implement univariate polynomial representation
    - Create UnivariatePolynomial<F> with coefficient storage
    - Implement evaluation using Horner's method in O(d) time
    - Implement addition and scalar multiplication
    - _Requirements: 1.5, 26.5_
  
  - [ ] 4.2 Implement FFT-based polynomial multiplication
    - Implement radix-2 Cooley-Tukey FFT algorithm
    - Support in-place computation for memory efficiency
    - Implement bit-reversal permutation
    - Multiply degree-d polynomials in O(d log d) time
    - _Requirements: 19.2, 26.6-26.7_
  
  - [ ] 4.3 Implement multilinear polynomial representation
    - Create MultilinearPolynomial<F> storing evaluations over Boolean hypercube B^μ
    - Store as Vec<F> of size 2^μ representing f(x) for all x ∈ B^μ
    - Implement from_evaluations constructor
    - _Requirements: 1.5, 41.1_
  
  - [ ] 4.4 Implement multilinear polynomial evaluation
    - Evaluate at arbitrary point r ∈ F^μ using dynamic programming
    - Achieve O(2^μ) field operations complexity
    - Reuse intermediate computations for efficiency
    - _Requirements: 1.5, 26.1-26.2_

- [ ] 5. Implement multilinear extension and eq function
  - [ ] 5.1 Implement eq function computation
    - Implement eq(x,X) = ∏^μ_{i=1}(x_iX_i + (1-x_i)(1-X_i)) exactly as specified
    - Support x ∈ B^μ (Boolean) and X ∈ F^μ (field elements)
    - Optimize for repeated evaluations
    - _Requirements: 1.6, 31.1_
  
  - [ ] 5.2 Implement eq table precomputation
    - Create EqTable<F> struct caching eq(·, r) values for fixed r
    - Precompute all 2^μ values in O(2^μ) time using recursive doubling
    - Provide O(1) lookup by Boolean vector index
    - _Requirements: 19.4, 26.3_
  
  - [ ] 5.3 Implement multilinear extension construction
    - Implement f̃(X) = ∑_{x∈B^μ} f(x) · eq(x,X) exactly as specified
    - Verify uniqueness property: f̃ is the only multilinear polynomial agreeing with f on B^μ
    - _Requirements: 1.5, 31.2_

- [ ]* 6. Write unit tests for cryptographic primitives
  - Test field arithmetic with edge cases (0, 1, -1, p-1)
  - Test batch inversion correctness and performance
  - Test group operations (addition, doubling, scalar mul, MSM)
  - Test polynomial operations (evaluation, multiplication, FFT)
  - Test eq function and multilinear extension properties
  - Property-based tests for algebraic properties
  - _Requirements: 21.1_

## Phase 2: Polynomial Commitment Scheme (SamaritanPCS)

- [ ] 7. Implement polynomial commitment scheme interface
  - Define PolynomialCommitmentScheme trait with setup, commit, open, verify
  - Define Commitment<G>, Proof, PublicParameters types
  - Support additive homomorphism: [[a]] + [[b]] = com_a · com_b
  - Support scalar multiplication: k · [[a]] = com_a^k
  - _Requirements: 1.2-1.4, 1.7, 12.1-12.6_

- [ ] 8. Implement SamaritanPCS for multilinear polynomials
  - [ ] 8.1 Implement trusted setup for SamaritanPCS
    - Generate structured reference string (SRS) for polynomials up to degree 2^μ
    - Store SRS as public parameters pp
    - Support BN254 curve with G1 and G2 groups
    - _Requirements: 12.1_
  
  - [ ] 8.2 Implement commitment operation
    - Commit to multilinear polynomial f ∈ F^{(≤1)}_μ
    - Compute com_f ← g^{f(s)} where s is secret in SRS
    - Achieve O(2^μ) group operations (linear prover time)
    - _Requirements: 1.2, 12.2_
  
  - [ ] 8.3 Implement opening operation
    - Generate evaluation proof (z, π_f) ← Open(pp, com_f, x) where z = f(x)
    - Produce constant-size proof: O(1) group elements
    - _Requirements: 1.3, 12.3_
  
  - [ ] 8.4 Implement verification operation
    - Verify pairing equation: e(com_f, g) = e(proof, h) · e(g, g)^z
    - Achieve O(μ) field operations + O(1) pairings
    - Return true if and only if f(x) = z with probability 1 - negl(λ)
    - _Requirements: 1.4, 12.4_
  
  - [ ] 8.5 Implement homomorphic operations
    - Implement commitment addition: add_commitments(c1, c2) → c1 · c2
    - Implement scalar multiplication: scalar_mul_commitment(k, c) → c^k
    - Verify homomorphic properties in tests
    - _Requirements: 1.7, 12.5-12.6_

- [ ]* 9. Write unit tests for polynomial commitment scheme
  - Test setup generates valid public parameters
  - Test commit-open-verify cycle for various polynomials
  - Test homomorphic properties: [[a+b]] = [[a]] + [[b]]
  - Test binding property (cannot open to two different values)
  - Test soundness (invalid openings are rejected)
  - _Requirements: 21.1_


## Phase 3: Sum-Check Protocol (Single Prover)

- [ ] 10. Implement transcript management for Fiat-Shamir
  - [ ] 10.1 Create Transcript<F> struct
    - Store all protocol messages as Vec<Vec<u8>>
    - Implement append_message(label, data) with domain separation
    - Implement get_challenge() → F using hash function H(label || transcript)
    - _Requirements: 15.1-15.7, 25.1-25.7_
  
  - [ ] 10.2 Implement hash-to-field function
    - Use SHA-256 or BLAKE2b as cryptographic hash
    - Map hash output to field element in F
    - Ensure uniform distribution over field
    - Support domain separation for different protocol phases
    - _Requirements: 15.2, 34.3_
  
  - [ ] 10.3 Implement transcript serialization
    - Use canonical encoding for field elements (32 bytes little-endian)
    - Use compressed encoding for group elements
    - Ensure deterministic challenge generation
    - _Requirements: 25.5-25.6_

- [ ] 11. Implement sum-check protocol prover
  - [ ] 11.1 Create SumCheckProtocol<F> struct
    - Store num_vars (μ), degree (d), and structure function h
    - Define SumCheckProof containing round polynomials
    - _Requirements: 2.1_
  
  - [ ] 11.2 Implement round polynomial computation
    - For round k ∈ [μ], compute univariate Q_k(X) of degree ≤ d
    - Use dynamic programming to achieve O(2^{μ-k+1} · d) time per round
    - Maintain table of partial evaluations for reuse
    - _Requirements: 2.2, 19.1, 26.2_
  
  - [ ] 11.3 Implement Algorithm 1 for product polynomial evaluation
    - Compute h(X) = ∏ᵢ₌₁ᵈ gᵢ(X) for linear univariate functions gᵢ
    - Use binary tree multiplication with FFT
    - Achieve O(d log d) complexity
    - _Requirements: 14.1-14.5, 37.1_
  
  - [ ] 11.4 Implement complete prover algorithm
    - Execute μ rounds, sending Q_k(X) in each round
    - Receive challenge r_k ← F from transcript
    - Reduce to final evaluation Q(r_b) where r_b = (r₁,...,r_μ)
    - Total prover time: O(2^μ · d) field operations
    - _Requirements: 2.2, 2.5_

- [ ] 12. Implement sum-check protocol verifier
  - [ ] 12.1 Implement round verification checks
    - Verify Q_{k-1}(r_{k-1}) = Q_k(0) + Q_k(1) for each round k
    - Generate random challenge r_k ← F using transcript
    - _Requirements: 2.3-2.4_
  
  - [ ] 12.2 Implement final verification
    - Verify Q_μ(r_μ) = h(w₀(r),...,w_{t-1}(r)) where r = (r₁,...,r_μ)
    - Query polynomial commitments at point r
    - Accept if all checks pass, reject otherwise
    - _Requirements: 2.5_
  
  - [ ] 12.3 Implement soundness analysis
    - Ensure knowledge error ≤ dμ/|F|
    - Verify perfect completeness (honest prover always accepted)
    - _Requirements: 2.6-2.7, 18.5_

- [ ]* 13. Write unit tests for sum-check protocol
  - Test with various degrees d ∈ {2, 3, 5} and variables μ ∈ {4, 8, 12}
  - Test honest prover is always accepted (completeness)
  - Test invalid proofs are rejected (soundness)
  - Test with different structure functions h
  - Benchmark prover time and verify O(2^μ · d) complexity
  - _Requirements: 21.1_

## Phase 4: SumFold Protocol (Single Prover)

- [ ] 14. Implement SumFold protocol for folding M instances
  - [ ] 14.1 Create SumFoldProtocol<F> struct
    - Store num_instances (M = 2^ν), num_vars (μ)
    - Define input: M sum-check instances with witnesses
    - Define output: single folded instance with witness
    - _Requirements: 3.1_
  
  - [ ] 14.2 Implement interpolation polynomial computation
    - Compute f_j(b,x) = ∑_{i∈[M]} eq(b,⟨i⟩_ν) · w_{i,j}(x) for j ∈ [t], b ∈ B^ν, x ∈ B^μ
    - Use precomputed eq table for efficiency
    - Store as (ν+μ)-variate multilinear polynomial
    - _Requirements: 3.3, 31.4_
  
  - [ ] 14.3 Implement aggregated sum computation
    - Compute T₀ = ∑_{i∈[M]} eq(ρ,⟨i⟩_ν) · v_i where ρ ← F^ν
    - Use eq table for O(M) complexity
    - _Requirements: 3.4, 31.6_
  
  - [ ] 14.4 Implement sum-check on folding polynomial
    - Define Q(b) = eq(ρ,b) · (∑_{x∈B^μ} h(f₀(b,x),...,f_{t-1}(b,x)))
    - Run ν-round sum-check proving ∑_{b∈B^ν} Q(b) = T₀
    - Reduce to Q(r_b) = c where r_b ∈ F^ν
    - _Requirements: 3.5-3.7, 31.5_
  
  - [ ] 14.5 Implement witness folding
    - Compute folded witness: w'_j = ∑_{i∈[M]} eq(r_b,⟨i⟩_ν) · w_{i,j} for j ∈ [t]
    - Compute folded commitments: [[w'_j]] = ∑_{i∈[M]} eq(r_b,⟨i⟩_ν) · [[w_{i,j}]]
    - Compute folded value: v' = c · eq(ρ,r_b)^{-1}
    - _Requirements: 3.8-3.11, 31.7-31.8_

- [ ]* 15. Write unit tests for SumFold protocol
  - Test folding M ∈ {2, 4, 8} instances
  - Verify folded instance satisfies relation
  - Test with different structure functions
  - Measure prover time and verify O(M · 2^μ) complexity
  - Measure proof size and verify O(log M) field elements
  - _Requirements: 21.1_


## Phase 5: HyperPlonk Constraint System

- [ ] 16. Implement HyperPlonk constraint system representation
  - [ ] 16.1 Create HyperPlonkConstraintSystem<F> struct
    - Define public parameters: (F, ℓ, n, ℓ_w, ℓ_q, f) where n=2^μ, ℓ=2^{ν_p}, ℓ_w=2^{ν_w}, ℓ_q=2^{ν_q}
    - Store gate function f : F^{ℓ_q+ℓ_w} → F of degree d
    - Store permutation σ : B^{μ+ν_w} → B^{μ+ν_w}
    - _Requirements: 6.1_
  
  - [ ] 16.2 Define HyperPlonk instance and witness types
    - Create HyperPlonkInstance<F,G> with public inputs p and witness commitment [[w]]
    - Create HyperPlonkWitness<F> with witness polynomial w
    - Ensure witness w ∈ F^{(≤1)}_{μ+ν_w} is multilinear
    - _Requirements: 6.2_
  
  - [ ] 16.3 Implement gate identity constraint
    - Compute virtual polynomial f̃(X) := f(q(⟨0⟩_{ν_q},X),...,q(⟨ℓ_q-1⟩_{ν_q},X), w(⟨0⟩_{ν_w},X),...,w(⟨ℓ_w-1⟩_{ν_w},X))
    - Verify f̃(X) = 0 for all X ∈ B^μ
    - Support vanilla Plonk gates with degree d ≤ 3
    - _Requirements: 6.3, 31.3, 34.5_
  
  - [ ] 16.4 Implement wire identity constraint (permutation)
    - Verify w(σ(x)) = w(x) for all x ∈ B^{μ+ν_w}
    - Store permutation as mapping Vec<usize>
    - _Requirements: 6.4_
  
  - [ ] 16.5 Implement consistency check constraint
    - Verify p(X) = w(0^{μ+ν_w-ν_p},X) for all X ∈ B^{ν_p}
    - Ensure public inputs match witness values
    - _Requirements: 6.5_

- [ ] 17. Implement circuit builder utilities
  - [ ] 17.1 Create Circuit builder API
    - Provide add_gate(gate_type, wires) method
    - Support gate types: Add, Mul, Custom
    - Automatically assign wire indices and build permutation
    - _Requirements: 16.1-16.2_
  
  - [ ] 17.2 Implement witness generation
    - Execute circuit on inputs to compute all wire values
    - Validate witness satisfies all gate constraints locally
    - Generate witness polynomial w from wire values
    - _Requirements: 16.3_
  
  - [ ] 17.3 Support data-parallel circuit structure
    - Accept M identical subcircuits C₀,...,C_{M-1} each of size T=N/M
    - Ensure structural homogeneity (same f, σ, q across subcircuits)
    - Allow different witness values w_i and public inputs p_i per subcircuit
    - _Requirements: 16.1-16.5_

- [ ]* 18. Write unit tests for HyperPlonk constraint system
  - Test simple circuits: addition gate, multiplication gate
  - Test circuit with multiple gates and wire connections
  - Test witness generation and validation
  - Test data-parallel circuit with M=4 subcircuits
  - Verify all three constraint types (gate, wire, consistency)
  - _Requirements: 21.1-21.2_

## Phase 6: Reduction Protocols

- [ ] 19. Implement zerocheck reduction (R_ZERO → R_HSUM)
  - [ ] 19.1 Create ZerocheckReduction<F> struct
    - Define R_ZERO relation: accepts ([[f]]; f) where f(x)=0 for all x ∈ B^μ
    - Store num_vars (μ) and degree (d)
    - _Requirements: 7.1, 41.2_
  
  - [ ] 19.2 Implement reduction algorithm (Protocol D.1)
    - Verifier samples random vector r ← F^μ
    - Prover computes eq polynomial [[e_r]] where e_r = eq(·,r)
    - Transform to sum-check: ∑_{x∈B^μ} f(x) · eq(x,r) = 0
    - Output instance: x = (0, [[f]], [[e_r]])
    - Output witness: w = f
    - Updated structure: h'({w̃_j}_{j∈[t]}, g) = h({w̃_j}_{j∈[t]}) · g
    - _Requirements: 7.2-7.6, 37.6_
  
  - [ ] 19.3 Verify public reducibility
    - Compute output instance from input [[f]] and transcript containing r
    - Ensure deterministic computation from public data
    - _Requirements: 7.6_

- [ ] 20. Implement permutation check reduction (R_PERM → R_HSUM)
  - [ ] 20.1 Create PermutationCheckReduction<F> struct
    - Define R_PERM relation: accepts (σ; ([[f]], [[g]]); (f, g)) where g(x)=f(σ(x))
    - Store permutation σ and num_vars (μ)
    - _Requirements: 8.1, 41.3_
  
  - [ ] 20.2 Implement identity and permutation polynomials
    - Verifier samples α, β ← F
    - Compute f_id = s_id + α · w + β (identity selector)
    - Compute f_σ = s_σ + α · w + β (permutation selector)
    - Obtain commitments [[f_id]] and [[f_σ]] homomorphically
    - _Requirements: 8.2-8.5, 31.11-31.12_
  
  - [ ] 20.3 Implement accumulator polynomial computation
    - Compute v ∈ F^{(≤1)}_{μ+1} where:
      - v(0,x) = f_id(x)/f_σ(x) for all x ∈ B^μ
      - v(1,x) = v(x,0) · v(x,1) for all x ∈ B^μ
    - Use batch inversion for computing ratios efficiently
    - _Requirements: 8.6, 31.13_
  
  - [ ] 20.4 Implement constraint polynomial and reduction
    - Verify v(1,...,1,0) = 1 (product of all ratios equals 1)
    - Compute ĝ(x₀,x) = (1-x₀)·(v(1,x) - v(x,0)·v(x,1)) + x₀·(f_σ(x)·v(0,x) - f_id(x))
    - Reduce to zerocheck on ĝ
    - Output: x = (0, [[f̂]], [[ê]]) and w = f̂
    - _Requirements: 8.7-8.11, 31.14, 37.7_

- [ ] 21. Implement consistency check reduction (R_CON → R_HSUM)
  - [ ] 21.1 Create ConsistencyCheckReduction<F> struct
    - Define R_CON relation: accepts ((p, [[w]]); w) where p(X)=w(0^{μ-ν_p},X)
    - Store num_public_vars (ν_p) and num_witness_vars (μ)
    - _Requirements: 9.1, 41.4_
  
  - [ ] 21.2 Implement single-prover reduction
    - Compute difference polynomial: [[w']] = [[w(0^{μ-ν_p},·)]] − [[p]]
    - Run zerocheck reduction on w' (should be zero if consistent)
    - Output sum-check instance
    - _Requirements: 9.3-9.4_

- [ ]* 22. Write unit tests for reduction protocols
  - Test zerocheck with zero and non-zero polynomials
  - Test permutation check with identity and non-identity permutations
  - Test consistency check with matching and mismatching public inputs
  - Verify reductions preserve relation membership
  - Test composition of reductions
  - _Requirements: 21.1_


## Phase 7: Network Communication Layer

- [ ] 23. Implement network protocol interface
  - [ ] 23.1 Define Network trait
    - Define async methods: send, receive, broadcast, barrier
    - Support message types: Challenge, PartialPoly, Commitment, WitnessShare, FinalProof
    - Define error types: ConnectionFailed, MessageTimeout, InvalidMessage
    - _Requirements: 17.1-17.7, 45.1-45.8_
  
  - [ ] 23.2 Create Message enum and serialization
    - Define Message enum with all protocol message types
    - Implement length-prefixed encoding: [4-byte length][1-byte type][2-byte sequence][payload][4-byte checksum]
    - Include sequence numbers for ordering
    - Add CRC32 checksum for integrity
    - _Requirements: 33.1-33.7, 45.2-45.5_
  
  - [ ] 23.3 Implement field and group element serialization
    - Serialize field elements as 32 bytes (little-endian)
    - Serialize G1 points as 33 bytes (compressed)
    - Serialize G2 points as 65 bytes (compressed)
    - Validate on deserialization (range check, curve check)
    - _Requirements: 33.1-33.7_

- [ ] 24. Implement TCP network backend
  - [ ] 24.1 Create TcpNetwork struct implementing Network trait
    - Establish TCP connections between provers
    - Maintain connection pool with prover ID → socket mapping
    - Support both client and server roles
    - _Requirements: 45.1_
  
  - [ ] 24.2 Implement reliable message delivery
    - Send messages with retry logic (up to 3 attempts)
    - Use exponential backoff: 1s, 2s, 4s
    - Implement timeout detection (30 seconds default)
    - Handle connection failures gracefully
    - _Requirements: 20.7, 28.4-28.6, 45.6-45.7_
  
  - [ ] 24.3 Implement flow control
    - Use sliding window protocol to prevent buffer overflow
    - Implement backpressure when receiver is slow
    - Monitor bandwidth usage per prover
    - _Requirements: 45.8_

- [ ] 25. Implement message routing and topology
  - [ ] 25.1 Create ProverTopology struct
    - Store prover count M = 2^ν and prover ID
    - Implement binary tree routing for round k: P_s → P_{2^{ν-k}+s}
    - Implement star topology for aggregation: all → P₀
    - Maintain routing table: prover ID → network address
    - _Requirements: 17.1-17.2, 28.1_
  
  - [ ] 25.2 Implement barrier synchronization
    - Coordinate provers at round boundaries
    - Ensure all provers complete round k before starting k+1
    - Detect stragglers and timeout
    - _Requirements: 28.2-28.3_
  
  - [ ] 25.3 Implement coordinator role (P₀)
    - Aggregate partial polynomials from active provers
    - Broadcast challenges to active provers
    - Manage protocol state machine
    - _Requirements: 4.7-4.9, 28.1_

- [ ]* 26. Write unit tests for network layer
  - Test message serialization/deserialization round-trip
  - Test TCP connection establishment and teardown
  - Test message delivery with simulated network delays
  - Test retry logic with simulated failures
  - Test barrier synchronization with M=4 provers
  - Test routing for different round numbers
  - _Requirements: 21.1_

## Phase 8: Distributed SumFold Protocol

- [ ] 27. Implement distributed SumFold prover
  - [ ] 27.1 Create DistributedSumFold<F,N> struct
    - Store prover_id, num_provers (M), network handle
    - Store local instance and witnesses
    - Maintain protocol state across rounds
    - _Requirements: 4.1_
  
  - [ ] 27.2 Implement initialization phase
    - Receive randomness ρ ∈ F^ν from verifier (via coordinator)
    - Compute and store eq(ρ,⟨i⟩_ν) for local prover i
    - Store local witness slices: f_j(⟨i⟩_ν,x) = w_{i,j}(x)
    - _Requirements: 4.2_
  
  - [ ] 27.3 Implement round k communication (worker prover)
    - For P_s (s ∈ [2^{ν-k}]), send to P_{2^{ν-k}+s}:
      - eq(ρ,{r₁,...,r_{k-1}}||⟨s⟩_{ν-k+1})
      - f_j({r₁,...,r_{k-1}}||⟨s⟩_{ν-k+1},x) for all x ∈ B^μ, j ∈ [t]
    - Serialize and transmit O(T) field elements
    - _Requirements: 4.3_
  
  - [ ] 27.4 Implement partial polynomial computation
    - For P_{2^{ν-k}+s}, receive data from P_s
    - Compute partial eq: e_k^{(s)}(X) = (1-X)·eq(ρ,{r₁,...,r_{k-1}}||0||⟨s⟩_{ν-k}) + X·eq(ρ,{r₁,...,r_{k-1}}||1||⟨s⟩_{ν-k})
    - Compute witness interpolation: f_{k,x}^{(s,j)}(X) = (1-X)·f_j({r₁,...,r_{k-1}}||0||⟨s⟩_{ν-k},x) + X·f_j({r₁,...,r_{k-1}}||1||⟨s⟩_{ν-k},x)
    - Compute Q_k^{(s)}(X) = e_k^{(s)}(X) · ∑_{x∈B^μ} h(f_{k,x}^{(s,0)}(X),...,f_{k,x}^{(s,t-1)}(X))
    - Use Algorithm 1 for efficient product evaluation
    - _Requirements: 4.4-4.6, 31.9-31.10, 37.3_
  
  - [ ] 27.5 Implement coordinator aggregation
    - P₀ receives Q_k^{(s)}(X) from all 2^{ν-k} active provers
    - Aggregate: Q_k(X) = ∑_{s∈[2^{ν-k}]} Q_k^{(s)}(X)
    - Send Q_k(X) to verifier (transcript)
    - Receive challenge r_k from verifier
    - Broadcast r_k to all active provers
    - _Requirements: 4.7-4.9_
  
  - [ ] 27.6 Implement next-round data computation
    - Each active prover computes:
      - eq(ρ,{r₁,...,r_k}||⟨s⟩_{ν-k})
      - f_j({r₁,...,r_k}||⟨s⟩_{ν-k},x) for all x ∈ B^μ, j ∈ [t]
    - P_{2^{ν-k}+s} sends updated data to P_s
    - _Requirements: 4.10_
  
  - [ ] 27.7 Implement final round and witness folding
    - After ν rounds, P₀ obtains eq(ρ,r_b) and f_j(r_b,x) where r_b = {r₁,...,r_ν}
    - Compute c = Q(r_b)
    - Each P_i computes: e_i = eq(r_b,⟨i⟩_ν), ([[w'_{i,j}]], w'_{i,j}) = (e_i·[[w_{i,j}]], e_i·w_{i,j})
    - Send [[w'_{i,j}]] to P₀
    - _Requirements: 4.11-4.12_
  
  - [ ] 27.8 Implement witness aggregation (binary tree)
    - For i ∈ [M-1]: P_i updates w'_j ← w'_j + w'_{M-i-1,j}
    - P_i sends w'_j to P_{M-i-2}
    - P₀ obtains final folded witness
    - Compute v' = c · eq(ρ,r_b)^{-1}
    - Compute [[w'_j]] = ∑_{i∈[M]} [[w'_{i,j}]]
    - _Requirements: 4.13-4.14_

- [ ] 28. Implement distributed SumFold verifier
  - [ ] 28.1 Implement verifier-side aggregation
    - Receive Q_k(X) from coordinator in each round k
    - Verify Q_{k-1}(r_{k-1}) = Q_k(0) + Q_k(1)
    - Generate challenge r_k ← F using transcript
    - _Requirements: 4.8_
  
  - [ ] 28.2 Implement verifier output computation
    - Compute v' = c · eq(ρ,r_b)^{-1}
    - Compute e_i = eq(r_b,⟨i⟩_ν) for all i ∈ [M]
    - Compute [[w'_j]] = ∑_{i∈[M]} e_i · [[w_{i,j}]] for j ∈ [t]
    - _Requirements: 4.15_

- [ ] 29. Verify complexity guarantees
  - [ ] 29.1 Measure and verify prover complexity
    - Each P_i (i ≠ 0): O(T) field ops + O(T) group ops where T=N/M
    - Coordinator P₀: O(T) field ops + O(T) group ops + O(M) group ops
    - _Requirements: 5.1-5.3, 40.1-40.2_
  
  - [ ] 29.2 Measure and verify communication complexity
    - Total communication: O(N) field elements + O(M) group elements
    - Per round: Each active prover sends O(T) field elements
    - _Requirements: 5.4, 17.6, 40.3_
  
  - [ ] 29.3 Measure and verify proof size
    - Proof size: O(log M) = O(ν) field elements
    - _Requirements: 5.5, 40.4_
  
  - [ ] 29.4 Measure and verify verifier complexity
    - Field operations: O(log M)
    - Multi-scalar multiplication: O(M)-size MSM
    - _Requirements: 5.6-5.7, 40.5_

- [ ]* 30. Write integration tests for distributed SumFold
  - Test with M ∈ {2, 4, 8} provers
  - Test with circuit sizes N ∈ {2^10, 2^12, 2^14}
  - Verify folded instance satisfies relation
  - Test with simulated network latency (1ms, 10ms, 50ms)
  - Test failure handling (prover crash, network partition)
  - Benchmark and verify complexity bounds
  - _Requirements: 21.2-21.4_


## Phase 9: Distributed Consistency Check

- [ ] 31. Implement distributed consistency check reduction
  - [ ] 31.1 Create DistributedConsistencyCheck<F,N> struct
    - Store prover_id, num_provers, network handle
    - Store local public input p_i and witness w_i
    - _Requirements: 9.2_
  
  - [ ] 31.2 Implement local difference computation
    - Each P_i computes: [[w'_i]] = [[w_i(0^{μ-ν_p},·)]] − [[p_i]]
    - Compute difference using homomorphic subtraction
    - _Requirements: 9.3_
  
  - [ ] 31.3 Implement distributed zerocheck reduction
    - Each P_i runs zerocheck reduction (Protocol D.1) on w'_i
    - Input: ([[w'_i]]; w'_i)
    - Output: ((0, [[w'_i]], [[e'_i]]); w'_i) with updated structure h₁
    - _Requirements: 9.4, 37.4_
  
  - [ ] 31.4 Implement distributed folding of zerocheck instances
    - Run distributed SumFold (Protocol 3.2) with structure h₁
    - Input for P_i: ((0, [[w'_i]], [[e'_i]]); w'_i)
    - Output: ((0, [[w']], [[e']]); w') with updated structure h'_c
    - _Requirements: 9.5, 37.4_
  
  - [ ] 31.5 Verify complexity guarantees
    - Each P_i: O(T) field ops + O(T) group ops
    - Communication: O(N) field elements
    - Proof size: O(log M) field elements
    - Verifier: O(log M) field ops + O(M) MSM
    - _Requirements: 9.6-9.9_

- [ ]* 32. Write integration tests for distributed consistency check
  - Test with M ∈ {2, 4, 8} provers
  - Test with matching public inputs (should pass)
  - Test with mismatching public inputs (should fail)
  - Verify complexity bounds
  - _Requirements: 21.2_

## Phase 10: Complete Distributed SNARK Protocol

- [ ] 33. Implement complete distributed SNARK orchestrator
  - [ ] 33.1 Create DistributedSNARK<F,G,N> struct
    - Store prover_id, num_provers, constraint_system, pcs, network
    - Store local instance and witness
    - Maintain protocol state machine
    - _Requirements: 10.1_
  
  - [ ] 33.2 Implement protocol state machine
    - States: INIT → INDEXED → READY → PROVING → COMPLETE
    - Substates during proving: GATE_REDUCTION, WIRE_REDUCTION, GATE_FOLDING, WIRE_FOLDING, CONSISTENCY_FOLDING, FINAL_SUMCHECK
    - Validate state transitions
    - _Requirements: 32.1-32.10_
  
  - [ ] 33.3 Implement indexing phase
    - Each P_i runs HyperPlonk indexer
    - Store structure f and instance-witness pair ((p_i, [[w_i]]); w_i)
    - Compute witness slices: [[w_{i,j}]] := [[w_i(⟨j⟩_{ν_w},·)]] for j ∈ [ℓ_w]
    - _Requirements: 10.1-10.2_

- [ ] 34. Implement Step 1: Gate identity reduction (local)
  - Each P_i runs zerocheck reduction (Protocol D.1) independently
  - Input: structure f, ({[[w_{i,j}]]}_{j∈[ℓ_w]}; {w_{i,j}}_{j∈[ℓ_w]})
  - Output: ((0, {[[w_{i,j}]]}_{j∈[ℓ_w]}, [[e_i]]); {w_{i,j}}_{j∈[ℓ_w]}) with updated structure f'
  - Verify gate identity: f̃(X) = 0 for all X ∈ B^μ
  - _Requirements: 10.3, 37.5_

- [ ] 35. Implement Step 2: Wire identity reduction (local)
  - Each P_i runs permutation check reduction (Protocol D.2) independently
  - Input: structure h_id, (([[w_i]], [[w_i]]); w_i)
  - Output: ((0, [[ĝ_{i,1}]], [[ĝ_{i,2}]], [[ĝ_{i,3}]], [[ê_i]]); ĝ_{i,1}, ĝ_{i,2}, ĝ_{i,3}) with updated structure h'
  - Verify wire identity: w(σ(x)) = w(x) for all x ∈ B^{μ+ν_w}
  - _Requirements: 10.4, 37.5_

- [ ] 36. Implement Step 3: Gate identity folding (distributed)
  - Run distributed SumFold (Protocol 3.2) with structure f'
  - Input for P_i: ((0, {[[w_{i,j}]]}_{j∈[ℓ_w]}, [[e_i]]); {w_{i,j}}_{j∈[ℓ_w]})
  - Output: ((0, {[[w̃_j]]}_{j∈[ℓ_w]}, [[ẽ]]); {w̃_j}_{j∈[ℓ_w]})
  - Fold M gate identity instances into single instance
  - _Requirements: 10.5, 37.5_

- [ ] 37. Implement Step 4: Wire identity folding (distributed)
  - Run distributed SumFold (Protocol 3.2) with structure h'
  - Input for P_i: ((0, [[ĝ_{i,1}]], [[ĝ_{i,2}]], [[ĝ_{i,3}]], [[ê_i]]); ĝ_{i,1}, ĝ_{i,2}, ĝ_{i,3})
  - Output: ((0, [[ĝ₁]], [[ĝ₂]], [[ĝ₃]], [[ê]]); ĝ₁, ĝ₂, ĝ₃)
  - Fold M wire identity instances into single instance
  - _Requirements: 10.6, 37.5_

- [ ] 38. Implement Step 5: Consistency check folding (distributed)
  - Run distributed consistency check (Protocol 4.2) with structure h_id
  - Input for P_i: ((p_i, [[w_i]]); w_i)
  - Output: ((0, [[w']], [[e']]); w') with updated structure h'_c
  - Fold M consistency check instances into single instance
  - _Requirements: 10.7, 37.5_

- [ ] 39. Implement Step 6: Final sum-check (coordinator only)
  - [ ] 39.1 P₀ runs sum-check on gate identity instance
    - Verify (f'; (0, {[[w̃_j]]}_{j∈[ℓ_w]}, [[ẽ]]); {w̃_j}_{j∈[ℓ_w]}) ∈ R_HSUM
    - Generate sum-check proof
    - _Requirements: 10.8_
  
  - [ ] 39.2 P₀ runs sum-check on wire identity instance
    - Verify (h'; (0, [[ĝ₁]], [[ĝ₂]], [[ĝ₃]], [[ê]]); ĝ₁, ĝ₂, ĝ₃) ∈ R_HSUM
    - Generate sum-check proof
    - _Requirements: 10.9_
  
  - [ ] 39.3 P₀ runs sum-check on consistency check instance
    - Verify (h'_c; (0, [[w']], [[e']]); w') ∈ R_HSUM
    - Generate sum-check proof
    - _Requirements: 10.10_
  
  - [ ] 39.4 P₀ performs polynomial commitment openings
    - Open all committed polynomials at evaluation points
    - Generate opening proofs using PCS
    - Combine all proofs into final proof structure
    - _Requirements: 10.10_

- [ ] 40. Implement complete verifier
  - [ ] 40.1 Verify all folding transcripts
    - Verify gate identity folding (ν rounds)
    - Verify wire identity folding (ν rounds)
    - Verify consistency check folding (ν rounds)
    - _Requirements: 10.8-10.10_
  
  - [ ] 40.2 Verify all sum-check proofs
    - Verify gate identity sum-check (μ rounds)
    - Verify wire identity sum-check (μ rounds)
    - Verify consistency check sum-check (μ rounds)
    - _Requirements: 10.8-10.10_
  
  - [ ] 40.3 Verify all polynomial commitment openings
    - Verify all opening proofs using PCS.Verify
    - Check pairing equations
    - _Requirements: 10.10_
  
  - [ ] 40.4 Implement accept/reject decision
    - Accept if all checks pass
    - Reject if any check fails
    - Return verification result
    - _Requirements: 10.11-10.12_

- [ ] 41. Verify security properties
  - [ ] 41.1 Verify perfect completeness
    - Test that all valid proofs from honest provers are accepted
    - Probability of acceptance = 1 for valid proofs
    - _Requirements: 10.11, 18.1_
  
  - [ ] 41.2 Verify knowledge soundness
    - Ensure knowledge error ≤ negl(λ)
    - Document extractor construction
    - Verify extraction probability ≥ 1 - negl(λ)
    - _Requirements: 10.12, 18.2-18.3, 42.1-42.7_
  
  - [ ] 41.3 Verify succinctness
    - Proof size: O(log N) field elements + O(1) group elements
    - Verification time: O(log N) field ops + O(M) MSM + O(1) pairings
    - _Requirements: 10.13, 18.4_

- [ ] 42. Verify complexity guarantees for complete protocol
  - [ ] 42.1 Measure prover complexity
    - Each P_i (i ≠ 0): O(T) field ops + O(T) group ops
    - Coordinator P₀: O(T) field ops + O(T) group ops + O(M) group ops
    - _Requirements: 11.1-11.2, 40.1-40.2_
  
  - [ ] 42.2 Measure communication complexity
    - Total: O(N) field elements + O(M) group elements
    - _Requirements: 11.4, 40.3_
  
  - [ ] 42.3 Measure proof size
    - O(log N) field elements + O(1) group elements
    - Concrete size: 8.5-9.9 KB for circuits 2^18 to 2^22
    - _Requirements: 11.5, 23.2, 40.4_
  
  - [ ] 42.4 Measure verifier complexity
    - Field operations: O(log M) for folding + O(log N) for sum-check
    - Group operations: O(M) MSM + O(1) pairings
    - Concrete time: 4.05-5.08 ms for circuits 2^18 to 2^22
    - _Requirements: 11.6-11.7, 23.3, 40.5_
  
  - [ ] 42.5 Measure round complexity
    - Total rounds: ν + μ where ν = log M, μ = log T
    - _Requirements: 40.6_


- [ ]* 43. Write comprehensive integration tests
  - Test complete protocol with M ∈ {2, 4, 8} provers
  - Test with circuit sizes N ∈ {2^18, 2^19, 2^20, 2^21, 2^22}
  - Test with different gate types (addition, multiplication, custom)
  - Test data-parallel circuits with identical subcircuits
  - Verify valid proofs are accepted (completeness)
  - Verify invalid proofs are rejected (soundness)
  - Test with modified witnesses (should be detected)
  - Test with invalid permutations (should be detected)
  - Test with mismatching public inputs (should be detected)
  - _Requirements: 21.2-21.4_

## Phase 11: Optimization and Performance

- [ ] 44. Implement performance optimizations
  - [ ] 44.1 Optimize sum-check with dynamic programming
    - Maintain table of partial evaluations across rounds
    - Reuse intermediate computations
    - Reduce prover time from O(2^μ · μ · d) to O(2^μ · d)
    - _Requirements: 19.1_
  
  - [ ] 44.2 Optimize polynomial operations with FFT
    - Use radix-2 FFT for polynomial multiplication
    - Achieve O(d log d) instead of O(d²)
    - _Requirements: 19.2_
  
  - [ ] 44.3 Optimize field operations with batch inversion
    - Use Montgomery's trick for batch inversion
    - Reduce n inversions from O(n·I) to O(n·M + I)
    - _Requirements: 19.3_
  
  - [ ] 44.4 Optimize eq function with precomputation
    - Precompute eq(ρ, ·) table in O(2^μ) time
    - Provide O(1) lookup for repeated queries
    - _Requirements: 19.4_
  
  - [ ] 44.5 Optimize MSM with Pippenger's algorithm
    - Use bucket method with optimal window size
    - Reduce from O(M · log p) to O(M/log M · log p)
    - _Requirements: 19.7_
  
  - [ ] 44.6 Implement parallel computation within prover
    - Use rayon for data parallelism
    - Parallelize polynomial evaluation over hypercube
    - Parallelize sum-check round computation
    - Achieve near-linear speedup with number of cores
    - _Requirements: 19.6, 22.7_
  
  - [ ] 44.7 Implement memory streaming optimizations
    - Stream polynomial evaluations when possible
    - Avoid storing entire polynomials in memory
    - Reduce memory usage from O(2^μ) to O(1) for streaming ops
    - _Requirements: 19.5, 27.2_

- [ ] 45. Implement error handling and validation
  - [ ] 45.1 Implement parameter validation
    - Validate field size |F| ≥ 2^λ
    - Validate circuit size N is power of 2
    - Validate prover count M is power of 2
    - Validate degree bound d ≤ max_degree
    - _Requirements: 20.1-20.4_
  
  - [ ] 45.2 Implement runtime validation
    - Validate polynomial degrees
    - Validate commitment consistency
    - Validate challenge validity
    - Validate message ordering
    - _Requirements: 20.5-20.8_
  
  - [ ] 45.3 Implement error recovery
    - Retry network operations with exponential backoff
    - Detect and handle prover failures
    - Clean up resources on error
    - Provide descriptive error messages
    - _Requirements: 20.7-20.10_

- [ ] 46. Implement logging and monitoring
  - [ ] 46.1 Implement structured logging
    - Log protocol initialization with parameters
    - Log round completion with timing and data sizes
    - Log errors with context (prover ID, round, operation)
    - Support log levels: ERROR, WARN, INFO, DEBUG, TRACE
    - _Requirements: 29.7, 30.1-30.8_
  
  - [ ] 46.2 Implement performance metrics collection
    - Track prover time per round
    - Track communication volume per round
    - Track memory usage per prover
    - Track network latency between provers
    - _Requirements: 30.4-30.6_
  
  - [ ] 46.3 Implement monitoring and alerting
    - Detect prover failures
    - Detect network partitions
    - Alert on performance degradation
    - Alert on memory exhaustion
    - _Requirements: 30.3_

- [ ]* 47. Write performance benchmarks
  - [ ] 47.1 Benchmark cryptographic primitives
    - Benchmark field operations (add, mul, inv, batch_inv)
    - Benchmark group operations (add, scalar_mul, MSM)
    - Benchmark polynomial operations (eval, mul, FFT)
    - Benchmark commitment operations (commit, open, verify)
    - _Requirements: 21.5_
  
  - [ ] 47.2 Benchmark protocol components
    - Benchmark sum-check prover and verifier
    - Benchmark SumFold prover and verifier
    - Benchmark reduction protocols
    - _Requirements: 21.5_
  
  - [ ] 47.3 Benchmark complete distributed protocol
    - Benchmark with M ∈ {1, 2, 4, 8} provers
    - Benchmark with N ∈ {2^18, 2^19, 2^20, 2^21, 2^22} gates
    - Measure prover time, communication, proof size, verification time
    - Document hardware specs (CPU, RAM, network)
    - _Requirements: 21.5-21.10_
  
  - [ ] 47.4 Compare with existing systems
    - Compare with HyperPianist (target: 4.1-4.9× speedup with 8 machines)
    - Compare with Cirrus (proof size, communication)
    - Compare with HEKATON, Pianist, deVirgo (asymptotic complexity)
    - Generate comparison tables
    - _Requirements: 23.1-23.9_

## Phase 12: Documentation and Examples

- [ ] 48. Write API documentation
  - [ ] 48.1 Document all public APIs with rustdoc
    - Document all public structs, traits, functions
    - Include usage examples in doc comments
    - Document error conditions and return values
    - Document complexity guarantees
    - _Requirements: 36.1_
  
  - [ ] 48.2 Document protocol specifications
    - Document each protocol step in detail
    - Include mathematical formulations
    - Reference requirements and design sections
    - _Requirements: 36.2_
  
  - [ ] 48.3 Write usage examples
    - Example: Simple circuit (addition, multiplication)
    - Example: Data-parallel circuit with M subcircuits
    - Example: Distributed proving with multiple machines
    - Example: Proof verification
    - _Requirements: 36.3_

- [ ] 49. Write deployment documentation
  - [ ] 49.1 Document hardware requirements
    - Minimum and recommended specs per prover
    - Coordinator additional requirements
    - Network requirements (latency, bandwidth)
    - _Requirements: 36.6_
  
  - [ ] 49.2 Document configuration parameters
    - Security parameter λ
    - Circuit size N and prover count M
    - Network addresses and timeouts
    - Optimization flags
    - _Requirements: 29.1-29.10, 36.6_
  
  - [ ] 49.3 Document setup and deployment
    - Installation instructions
    - Configuration file format
    - Running distributed provers
    - Monitoring and troubleshooting
    - _Requirements: 36.6-36.7_

- [ ] 50. Write security documentation
  - [ ] 50.1 Document cryptographic assumptions
    - Discrete logarithm problem
    - Pairing assumptions
    - Random oracle model
    - Schwartz-Zippel lemma
    - _Requirements: 36.5_
  
  - [ ] 50.2 Document security properties
    - Perfect completeness proof
    - Knowledge soundness proof with extractor
    - Succinctness analysis
    - Concrete security parameters (λ=128)
    - _Requirements: 18.1-18.11, 24.1-24.10, 36.5, 44.1-44.7_
  
  - [ ] 50.3 Document threat model
    - Honest-but-curious provers
    - Malicious prover
    - Network adversary
    - Limitations (not zero-knowledge)
    - _Requirements: 36.5_

- [ ]* 51. Write performance documentation
  - Document benchmark results with tables and graphs
  - Document complexity analysis (theoretical and measured)
  - Document comparison with existing systems
  - Document optimization techniques and their impact
  - _Requirements: 36.4_

## Summary

This implementation plan provides a comprehensive roadmap for building the distributed SNARK system via folding schemes. The plan is organized into 12 phases with 51 top-level tasks and numerous subtasks, totaling approximately 15,000 lines of Rust code.

**Key Milestones:**
- Phase 1-3: Core cryptographic foundation (~4,000 LOC)
- Phase 4-6: Protocol components (~4,500 LOC)
- Phase 7-10: Distributed implementation (~4,500 LOC)
- Phase 11-12: Optimization and documentation (~2,000 LOC)

**Testing Strategy:**
- Unit tests for each component (marked with *)
- Integration tests for protocol composition
- Performance benchmarks for optimization validation
- Comparison benchmarks against existing systems

**Expected Performance:**
- 4.1-4.9× speedup over HyperPianist with 8 machines
- Proof size: 8.5-9.9 KB for circuits 2^18 to 2^22
- Verification time: 4.05-5.08 ms
- Linear prover time O(T) where T = N/M

The implementation follows the paper specification exactly, with all mathematical formulations implemented as specified in the requirements. Each task references specific requirements to ensure traceability and correctness.

