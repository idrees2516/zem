# Implementation Tasks: Complete Sum-Check Based SNARK with Twist and Shout

## Phase 1: Core Mathematical Primitives and Sum-Check Protocol

- [ ] 1.1 Implement Extension Field Framework
  - Implement ExtensionField trait with add, sub, mul, div, zero, one, inverse operations
  - Create struct storing t coefficients over base field Fq
  - Implement arithmetic modulo irreducible polynomial f(X) of degree t
  - Add to_base_field_coefficients() returning [a_0, ..., a_{t-1}]
  - Add from_base_field_element(a, i) embedding Fq into K at position i
  - Implement inverse using Extended Euclidean algorithm
  - Implement pow(n) using square-and-multiply
  - Add random() sampling uniformly from K
  - Verify field axioms: associativity, commutativity, distributivity, inverses
  - Add tests for K = F_q[X]/(X^2 + 1) with q = 2^61 - 1
  - _Requirements: 1.1, 1.2, 25.1, 25.2_

- [ ] 1.2 Implement Multilinear Polynomial over Extension Fields
  - Create MultilinearPolynomial<K> struct with evaluations: Vec<K>, num_vars: usize
  - Implement from_evaluations(evals: Vec<K>) validating length is power of 2
  - Implement evaluate(point: &[K]) computing ã(r) = Σ_{x∈{0,1}^n} a(x)·eq̃(r,x)
  - Implement eq_polynomial(r: &[K], x: &[bool]) computing Π_i ((1-r_i)(1-x_i) + r_i·x_i)
  - Implement partial_eval(r_0: K) returning (n-1)-variate MLE
  - Use formula: p̃(r_0,x') = (1-r_0)·p̃(0,x') + r_0·p̃(1,x')
  - Implement index_to_bits(idx, n) converting index to Boolean vector
  - Add to_tensor_of_rings() converting to lattice representation
  - Verify MLE uniqueness: two MLEs equal iff evaluations match on {0,1}^n
  - Add tests with n=4,8,10 variables
  - _Requirements: 1.2, 1.3, 1.4, 3.2_


- [ ] 1.3 Implement Tensor-of-Rings Bridge for Sum-Check and Folding
  - Create TensorOfRings<K,R> struct with matrix: Vec<Vec<Zq>>, extension_degree: t, ring_dimension: d
  - Implement as_k_vector() returning [e_1,...,e_d] ∈ K^d for sum-check operations
  - Algorithm: For each column j, compute k_elem = Σ_i matrix[i][j]·α^i where α generates K/Fq
  - Implement as_rq_module() returning (e'_1,...,e'_t) ∈ Rq^t for folding operations
  - Algorithm: For each row i, create ring element from coefficients matrix[i][:]
  - Implement k_scalar_mul(scalar: K) for sum-check scalar multiplication
  - Algorithm: Multiply by scalar coefficients with wraparound modulo extension degree
  - Implement rq_scalar_mul(scalar: R) for folding scalar multiplication
  - Algorithm: Multiply by ring coefficients with wraparound modulo ring dimension
  - Verify bidirectional conversion: as_k_vector().to_tensor() == original
  - Add tests converting between K-space and Rq-module representations
  - _Requirements: 1.1, 1.2, 2.1, 3.1_

- [ ] 1.4 Implement Dense Sum-Check Prover for Products
  - Create DenseSumCheckProver<K> with round: usize, p_evals: Vec<K>, q_evals: Vec<K>
  - Implement new(p: MLE<K>, q: MLE<K>) initializing with full evaluation tables
  - Validate p.num_vars == q.num_vars, store N = 2^n evaluations
  - Implement round_polynomial() computing s_i(X) of degree 2
  - Algorithm for round i with n_remaining = N/2^{i-1} terms:
    * Compute s(0) = Σ_{j=0}^{n_remaining/2-1} p_evals[j]·q_evals[j]
    * Compute s(1) = Σ_{j=0}^{n_remaining/2-1} p_evals[j+half]·q_evals[j+half]
    * Compute s(2) using extrapolation: p(2,x') = 2·p(1,x') - p(0,x')
    * Return UnivariatePolynomial from 3 evaluations
  - Implement update(challenge: K) binding variable to challenge
  - Algorithm: For j in 0..half: new_p[j] = (1-r)·p[j] + r·p[j+half]
  - Shrink arrays from size N/2^{i-1} to N/2^i
  - Implement final_evaluation() returning p_evals[0]·q_evals[0]
  - Verify total prover time is O(N) = O(2·N + N + N/2 + ... + 1)
  - Add tests with N=256,1024,4096
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 18C.1_


- [ ] 1.5 Implement Dense Sum-Check Verifier
  - Create DenseSumCheckVerifier<K> tracking claimed_sum: K, prev_poly: Option<UniPoly<K>>, challenges: Vec<K>
  - Implement verify_round_1(s_1: UniPoly<K>, claimed_sum: K) checking C = s_1(0) + s_1(1)
  - Implement verify_round_i(s_i: UniPoly<K>) for i>1 checking s_{i-1}(r_{i-1}) = s_i(0) + s_i(1)
  - Sample challenge r_i ← K uniformly at random
  - Store challenge and current polynomial for next round
  - Implement verify_final(s_n: UniPoly<K>, final_eval: K) checking s_n(r_n) = final_eval
  - Verify degree bounds: reject if deg(s_i) > 2
  - Compute total soundness error: 2n/|F| for n rounds
  - Return Accept/Reject with error probability bound
  - Add tests verifying honest prover always accepted
  - Add tests verifying cheating prover rejected with high probability
  - _Requirements: 2.1, 2.2, 2.6, 2.7, 2.8, 2.11, 2.12_

- [ ] 1.6 Implement Sparse Sum-Check with Prefix-Suffix Algorithm
  - Create SparseSumCheckProver<K> with sparse_entries: Vec<(usize,K)>, stage: usize, p_array: Vec<K>, q_array: Vec<K>
  - Implement new(sparse_p, f, h, c) for sparsity T and memory O(N^{1/c})
  - Stage 1 initialization with one streaming pass:
    * For each (idx, val) in sparse_p: compute (i,j) = split_index(idx, √N)
    * Accumulate P[i] += val·h[j]
    * Set Q[i] = f[i]
  - Execute first n/2 rounds of sum-check on P̃(i)·Q̃(i)
  - Stage 2 initialization after receiving challenges ⃗r:
    * Create new P,Q arrays of size √N
    * For each (idx, val): compute P[j] = p̃(⃗r,j), Q[j] = f̃(⃗r)·h̃(j)
  - Execute final n/2 rounds of sum-check
  - Verify total time O(T + √N) for c=2
  - Generalize to O(T + N^{1/c}) for arbitrary c
  - Add tests with T=1000, N=10^6, c=2,3,4
  - _Requirements: 4.1, 4.2, 4.3, 4.6, 4.7, 4.20, 11B.1_


## Phase 2: One-Hot Addressing and Shout Protocol

- [ ] 2.1 Implement One-Hot Address Encoding with Tensor Decomposition
  - Create OneHotAddress<K> with d: usize, chunk_size: usize, chunks: Vec<Vec<K>>
  - Implement encode(address: usize, K: usize, d: usize) decomposing into d chunks
  - Algorithm:
    * Compute chunk_size = ⌈K^{1/d}⌉
    * For each dimension i: digit = address % chunk_size, address /= chunk_size
    * Create one-hot vector with chunks[i][digit] = 1, rest = 0
  - Implement verify_one_hot() checking Σ_k chunk[k] = 1 and chunk[k] ∈ {0,1}
  - Implement to_full_vector() computing tensor product chunks[0] ⊗ ... ⊗ chunks[d-1]
  - Algorithm: Start with [1], for each chunk: result = [r·c for r,c in product]
  - Verify reconstruction: to_full_vector()[address] = 1, rest = 0
  - Test examples: (K=32,d=1), (K=1024,d=2), (K=2^20,d=4)
  - Measure commitment costs: d·K^{1/d} values per address
  - _Requirements: 11A.1, 11A.2, 11A.3, 11A.12, 11A.13, 11A.14_

- [ ] 2.2 Implement Shout Protocol Structure
  - Create ShoutProtocol<K,PCS> with memory_size: K, num_lookups: T, d: usize, access_commitments: Vec<Commitment>, table: MLE<K>
  - Implement new(K, T, d, pcs) initializing protocol parameters
  - Configure d based on memory size:
    * d=1 for K ≤ 2^16 (small tables)
    * d=2 for K ≤ 2^20 (medium tables)
    * d=4 for K ≤ 2^30 (large tables)
    * d=8 for K > 2^30 (gigantic tables)
  - Store lookup table as MLE-structured polynomial
  - Initialize commitment scheme with appropriate parameters
  - _Requirements: 9.1, 9.2, 9.28, 9.29, 9.30, 9.31_

- [ ] 2.3 Implement Shout Prover Commitment Phase
  - Implement prover_commit(addresses: &[usize], pcs: &PCS) committing to one-hot addresses
  - Algorithm for each dimension i ∈ {1,...,d}:
    * Create access matrix ra_i of size K^{1/d} × T
    * For each lookup j: encode address[j], set ra_i[digit_i, j] = 1
    * Flatten matrix: flat = ra_i.into_iter().flatten().collect()
    * Create MLE: mle_i = MultilinearPolynomial::from_evaluations(flat)
    * Commit: commitment_i = pcs.commit(&mle_i)
  - Store d commitments in access_commitments
  - Verify only d·T non-zero values committed (all 1s)
  - With elliptic curves: 0s are free, only pay for d·T group operations
  - Return commitments vector
  - _Requirements: 9.14, 9.28, 11A.15, 11A.16, 15A.1, 15A.2_


- [ ] 2.4 Implement Shout Read-Checking Sum-Check
  - Implement read_checking_sumcheck(rcycle: &[K], prover_state: &mut SparseSumCheckProver<K>) proving rv(r') = Σ_k ra(k,r')·Val(k)
  - Setup: Verifier samples rcycle ∈ F^{log T} uniformly at random
  - Execute sum-check over log K variables:
    * For round i=1 to log K:
      - Prover computes s_i(X) = Σ_{x'} ra(r_1,...,r_{i-1},X,x',rcycle)·Val(r_1,...,r_{i-1},X,x')
      - Exploit sparsity: only T out of 2^{log K} terms non-zero
      - Send s_i to verifier
      - Receive challenge r_i from verifier
      - Update sparse term list
  - Final evaluation: ra(raddress, rcycle)·Val(raddress)
  - Verifier computes Val(raddress) directly (MLE-structured table)
  - Prover provides ra(raddress, rcycle) from commitment
  - Verify total prover time O(K + T·log K)
  - Add tests with K=256, T=100; K=2^16, T=2^10
  - _Requirements: 9.12, 9.13, 9.16, 11B.4, 11B.5, 18C.9_

- [ ] 2.5 Implement Shout Booleanity Check
  - Implement booleanity_check(access_mle: &MLE<K>) verifying ra(k,j) ∈ {0,1} for all (k,j)
  - Apply zero-check PIOP to constraint: ra(k,j)² - ra(k,j) = 0
  - Setup: Define g(k,j) = ra(k,j)² - ra(k,j)
  - Verifier samples r ∈ F^{log K}, r' ∈ F^{log T}
  - Apply sum-check to prove Σ_{k,j} eq(r,k)·eq(r',j)·g(k,j) = 0
  - Exploit sparsity: only T out of K·T terms potentially non-zero
  - Prover time: O(K) + 2T field multiplications
  - Final check: Verify g(r,r') = ra(r,r')² - ra(r,r') = 0
  - Soundness error: (log K + log T)/|F|
  - Add tests verifying rejection of non-Boolean values
  - _Requirements: 9.19, 11B.14, 18C.6_


- [ ] 2.6 Implement Shout One-Hot Check
  - Implement one_hot_check(access_mle: &MLE<K>, rcycle: &[K]) verifying Σ_k ra(k,j) = 1 for all j
  - For non-binary fields (char(F) > 2):
    * Compute eval_point = [2^{-1}, ..., 2^{-1}, rcycle] where 2^{-1} is half in F
    * Evaluate ra at eval_point
    * Check K·ra(2^{-1},...,2^{-1},rcycle) = 1
    * Verifier time: O(1) evaluation query
  - For binary fields:
    * Apply sum-check to compute Σ_k ra(k,rcycle)
    * Verify sum equals 1
    * Verifier time: O(log K) sum-check rounds
  - Run in parallel with Booleanity check to share evaluation point
  - Soundness error: log T/|F|
  - Add tests for both field types
  - _Requirements: 9.20, 18B.28, 18B.29, 18C.7_

- [ ] 2.7 Implement Virtual Read Values for Shout
  - Create VirtualReadValues<K> with access_mle: MLE<K>, table_mle: MLE<K>
  - Implement VirtualPolynomial trait
  - Implement evaluate_via_sumcheck(rcycle: &[K]) computing rv(rcycle) = Σ_k ra(k,rcycle)·Val(k)
  - Algorithm:
    * Apply sum-check over k ∈ {0,1}^{log K}
    * Each round: compute s_i(X) = Σ_{x'} ra(r_1,...,r_{i-1},X,x',rcycle)·Val(r_1,...,r_{i-1},X,x')
    * Final: evaluate ra(raddress,rcycle) from commitment, Val(raddress) by verifier
  - Implement sumcheck_claim(rcycle) returning SumCheckClaim
  - Verify rv never explicitly committed - always computed via sum-check
  - Prover saves commitment costs: no commitment to T read values
  - Add tests comparing virtual vs explicit commitment
  - _Requirements: 9.15, 9.16, 10.9, 11C.1, 11C.9, 11C.10_

- [ ] 2.8 Implement Sparse-Dense Sum-Check for Gigantic Tables
  - Implement sparse_dense_sumcheck for K = T^C with C ≥ 1
  - Generalize sparse-dense protocol from Generalized-Lasso
  - For structured table Val where Val(k) computable in O(log K) time:
    * Decompose sum over k into C-dimensional structure
    * Process each dimension with O(T) work
    * Total prover time: O(C·T) instead of O(K + T)
  - Algorithm for C=2 (K = T²):
    * Stage 1: Process first √K variables in O(T) time
    * Stage 2: Process second √K variables in O(T) time
  - Extend to arbitrary C with d-dimensional tensor decomposition
  - Verify prover time O(C·T) for K = T^C
  - Add tests with K=2^20, T=2^10, C=2; K=2^64, T=2^16, C=4
  - _Requirements: 9.34, 9.35, 11B.9, 11B.10, 11B.11_


## Phase 3: Twist Protocol for Read-Write Memory

- [ ] 3.1 Implement Twist Protocol Structure with Increments
  - Create TwistProtocol<K,PCS> with memory_size: K, num_cycles: T, d: usize, read_address_commitments: Vec<Commitment>, write_address_commitments: Vec<Commitment>, increment_commitment: Commitment
  - Implement new(K, T, d, pcs) initializing protocol
  - Configure d based on memory size (same as Shout)
  - Initialize commitment scheme
  - Allocate storage for increments: Vec<K> of size T (sparse, small values)
  - _Requirements: 11.1, 11.2, 11.19, 11.20_

- [ ] 3.2 Implement Increment Computation
  - Implement compute_increment(k, j, write_address, write_value, current_value) computing Inc(k,j) = wa(k,j)·(wv(j) - Val(k,j))
  - Algorithm:
    * Compute wa_kj = Π_{ℓ=1}^d wa_ℓ(k_ℓ, j) from tensor product
    * If wa_kj = 0: return 0 (cell k not written at cycle j)
    * If wa_kj = 1: return wv(j) - Val(k,j)
  - Verify only T non-zero increments (at most one per cycle)
  - Verify increments are small (32-bit values for zkVM)
  - Store increments in sparse format: Vec<(cycle, value)>
  - Commit to increments using Neo pay-per-bit for small values
  - Add tests verifying increment correctness
  - _Requirements: 11.17, 11.18, 11.19, 11.20, 15A.19_

- [ ] 3.3 Implement Less-Than Predicate for Twist
  - Implement less_than_mle(log_t: usize) creating MLE of LT(j',j) = 1 iff j' < j
  - Algorithm:
    * Create evaluation table of size 2^{2·log T}
    * For each (j', j) pair: set LT(j',j) = 1 if j' < j as integers, else 0
    * Return MultilinearPolynomial from evaluations
  - Implement evaluate_less_than(r: &[K], r_prime: &[K]) computing LT̃(r',r)
  - Algorithm:
    * result = 0, prefix_prod = 1
    * For i=0 to n-1:
      - term = prefix_prod·(1-r'_i)·r_i  (bit i is first difference with r'_i < r_i)
      - result += term
      - prefix_prod *= r'_i·r_i + (1-r'_i)·(1-r_i)  (bits 0..i-1 equal)
    * Return result
  - Verify verifier computes in O(log T) time
  - Add tests with various (j',j) pairs
  - _Requirements: 11.21, 11.22, 12.2, 12.3, 12.4_


- [ ] 3.4 Implement Val-Evaluation Sum-Check
  - Implement val_evaluation_sumcheck(raddress: &[K], rcycle: &[K], increment_mle: &MLE<K>) computing Val(raddress, rcycle) = Σ_{j'} Inc(raddress,j')·LT(j',rcycle)
  - Setup: Create DenseSumCheckProver with increment_mle and less_than_mle
  - Execute sum-check over log T variables:
    * For round i=1 to log T:
      - Compute s_i(X) = Σ_{x'} Inc(raddress,r_1,...,r_{i-1},X,x')·LT(r_1,...,r_{i-1},X,x',rcycle)
      - Send s_i to verifier
      - Receive challenge r_i
      - Update arrays via partial evaluation
  - Final evaluation: Inc(raddress,r_j')·LT(r_j',rcycle)
  - Verifier obtains Inc(raddress,r_j') from commitment
  - Verifier computes LT(r_j',rcycle) in O(log T) time
  - Return Val(raddress,rcycle) to verifier
  - Verify prover time O(T) for dense case
  - Add tests with T=256,1024,4096
  - _Requirements: 11.23, 11.24, 12.1, 12.2, 12.5_

- [ ] 3.5 Implement Read-Checking Sum-Check for Twist
  - Implement read_checking_sumcheck(r': &[K]) proving rv(r') = Σ_{k,j} eq(r',j)·ra(k,j)·Val(k,j)
  - Setup: Verifier samples r' ∈ F^{log T}
  - Apply sum-check over (k,j) ∈ {0,1}^{log K} × {0,1}^{log T}:
    * For first log K rounds: bind memory address variables
    * For next log T rounds: bind time variables
    * Exploit sparsity: only T out of K·T terms non-zero (where ra≠0)
  - Final evaluation requires:
    * ra(raddress, rcycle) from commitment
    * Val(raddress, rcycle) via Val-evaluation sum-check
  - Run Val-evaluation in parallel with write-checking to share evaluation point
  - Verify prover time O(K + T·log K)
  - Add tests verifying read correctness
  - _Requirements: 11.25, 11.27, 13.1, 13.4, 18C.9_

- [ ] 3.6 Implement Write-Checking Sum-Check for Twist
  - Implement write_checking_sumcheck(r': &[K], r'': &[K]) proving Inc(r',r'') = Σ_{k,j} eq(r',k)·eq(r'',j)·wa(k,j)·(wv(j) - Val(k,j))
  - Setup: Verifier samples r' ∈ F^{log K}, r'' ∈ F^{log T}
  - Apply sum-check over (k,j) ∈ {0,1}^{log K} × {0,1}^{log T}
  - Constraint verification: Inc(k,j) = wa(k,j)·(wv(j) - Val(k,j))
  - Final evaluation requires:
    * Inc(r',r'') from commitment
    * wa(r',r'') from commitment
    * wv(r'') from commitment or as virtual polynomial
    * Val(r',r'') via Val-evaluation sum-check
  - Verify prover time O(K + T·log K)
  - Add tests verifying write correctness
  - _Requirements: 11.26, 11.27, 13.2, 13.3, 13.4_


- [ ] 3.7 Implement Locality-Aware Twist Prover
  - Create LocalityAwareTwistProver<K> with access_history: HashMap<usize, Vec<usize>>, current_sparsity: usize, round: usize
  - Implement process_operation(cell, time, is_write) tracking memory access patterns
  - Algorithm:
    * Find last_access_time for cell from access_history
    * If first access: cost = O(log K)
    * If accessed δ steps ago: cost = O(log δ)
    * Update access_history[cell].push(time)
    * Return locality_cost
  - Implement bind_time_first_order(log_k, log_t) returning variable binding order
  - Algorithm:
    * First log_t rounds: bind time variables (enables coalescing)
    * Next log_k rounds: bind memory variables
    * Return order = [0..log_t, log_t..log_t+log_k]
  - Implement sparsity tracking:
    * Track non-zero positions in current round
    * As time variables bound, temporally-close accesses coalesce
    * Sparsity falls quickly for local access patterns
  - Verify O(i) cost for accesses to cells accessed 2^i steps prior
  - Add tests with local vs random access patterns
  - Measure speedup for local accesses
  - _Requirements: 11.31, 11.32, 11.33, 11.34, 14.1, 14.2, 14.3, 14.4, 14.5, 14.6_

- [ ] 3.8 Implement Virtual Memory Values
  - Create VirtualMemoryValues<K> with increment_mle: MLE<K>, write_address_mle: MLE<K>
  - Implement VirtualPolynomial trait for Val(k,j)
  - Implement evaluate_via_sumcheck(point: &[K]) where point = (raddress, rcycle)
  - Algorithm:
    * Split point into raddress and rcycle
    * Apply sum-check: Val(raddress,rcycle) = Σ_{j'} Inc(raddress,j')·LT(j',rcycle)
    * Return result from sum-check
  - Implement sumcheck_claim(point) generating claim for Val evaluation
  - Verify Val never explicitly committed
  - Prover avoids K·T commitments, only commits T increments
  - Add tests comparing virtual vs explicit Val commitment
  - _Requirements: 11C.10, 11C.11, 11C.12, 11C.13, 11C.14, 15.1, 15.2, 15.3_


## Phase 4: Virtual Polynomials and Address Conversion

- [ ] 4.1 Implement Virtual Polynomial Framework
  - Create VirtualPolynomial<K> trait with evaluate_via_sumcheck(point, committed_polys) and sumcheck_claim(point)
  - Define interface for polynomials not directly committed
  - Implement chaining: virtual polynomial can depend on other virtual polynomials
  - Add support for nested sum-check reductions
  - Verify soundness: virtual polynomial evaluations provably correct
  - Add tests for various virtual polynomial types
  - _Requirements: 10.1, 10.2, 11C.1, 11C.18, 16.1, 16.2_

- [ ] 4.2 Implement Virtual Address Field Conversion
  - Create VirtualAddressField<K> with one_hot_chunks: Vec<MLE<K>>, chunk_size: usize
  - Implement conversion from one-hot encoding to field element
  - Implement evaluate_via_sumcheck(rcycle: &[K]) computing raf(rcycle) = Σ_k (Σ_i 2^i·k_i)·Π_ℓ ra_ℓ(k_ℓ,rcycle)
  - Algorithm:
    * Apply sum-check over k ∈ {0,1}^{log K}
    * For each k: compute address_value = Σ_i 2^{i·log(chunk_size)}·k_i
    * Multiply by product of one-hot indicators: Π_ℓ ra_ℓ(k_ℓ,rcycle)
    * Sum over all k
  - Support d-dimensional decomposition
  - Integrate with zkVM address specifications (single field element per address)
  - Verify raf never committed, always computed via sum-check
  - Add tests converting one-hot to field element
  - _Requirements: 11C.2, 11C.3, 11C.4, 11C.5, 11C.6, 17.1, 17.2, 17.3, 17.4_

- [ ] 4.3 Implement Virtual Write Values
  - Create VirtualWriteValues<K> expressing wv as virtual polynomial
  - Implement wv(j) = Σ_k wa(k,j)·(Val(k,j) + Inc(j))
  - Algorithm:
    * Apply sum-check over k ∈ {0,1}^{log K}
    * For each k: compute wa(k,j)·(Val(k,j) + Inc(j))
    * Val(k,j) itself is virtual, computed via increment aggregation
    * Sum over all k
  - Integrate with write-checking sum-check
  - Verify wv never committed
  - Add tests verifying write value correctness
  - _Requirements: 11.22, 11C.17, 18.1, 18.2_


## Phase 5: Lattice-Based Polynomial Commitments Integration

- [ ] 5.1 Implement HyperWolf Adapter for Twist and Shout
  - Create HyperWolfTwistShout<R> with ajtai_params, ipa_params, labrador_params
  - Implement commit_one_hot_address(address: &OneHotAddress) exploiting sparsity
  - Algorithm:
    * Only commit to d positions that are 1
    * Use sparse commitment: commit_sparse(&address.chunks, d)
    * Exploit that K^{1/d} - 1 positions are 0 (free)
    * Return Commitment<R>
  - Implement commit_increments(increments: &[K]) with small-value optimization
  - Algorithm:
    * Use Neo pay-per-bit for 32-bit values
    * Exploit that most increments are 0
    * Return Commitment<R>
  - Verify commitment costs: d group ops for addresses, T group ops for increments
  - Add tests measuring commitment time
  - _Requirements: 15.1, 15.2, 15.3, 19.1, 19.2, 19.3, 20.1_

- [ ] 5.2 Implement Sparse Polynomial Evaluation Proofs
  - Implement prove_evaluation_sparse(commitment, point, value, sparse_poly)
  - Integrate k-round witness folding:
    * Fold witness over k rounds
    * Each round: fold_witness(current, challenge)
    * Reduce to smaller witness
  - Apply Guarded IPA for exact ℓ₂-norm proof:
    * Prove ∥witness∥₂ exactly (not approximate)
    * Use Module-SIS hardness
    * Return IPA proof
  - Compress with LaBRADOR:
    * Apply recursive compression
    * Achieve O(log log log N) proof size
    * Return compressed proof
  - Verify evaluation proof correctness
  - Add tests with various sparsity levels
  - _Requirements: 15.4, 15.5, 19.4, 19.5, 19.6, 19.7_

- [ ] 5.3 Optimize Commitments for Small Values and Sparsity
  - Implement Neo pay-per-bit optimization for increments
  - Algorithm:
    * Decompose value into bits
    * Commit to bit-width instead of full value
    * Cost scales with log(value) not log(field_size)
  - Track sparsity throughout protocol:
    * Maintain list of non-zero positions
    * Only process non-zero terms in sum-check
    * Update sparsity as variables bound
  - Optimize for 0s (conceptually free with elliptic curves):
    * Skip 0 positions in commitment computation
    * Track but don't process in sum-check
  - Optimize for 1s (single group operation):
    * Use unit vector optimization
    * Batch process all 1s together
  - Optimize for 32-bit values (two group operations):
    * Use Pippenger's algorithm with small scalars
    * Achieve ~2 group ops per 32-bit value
  - Add benchmarks comparing optimized vs naive
  - _Requirements: 15A.1, 15A.2, 15A.3, 15A.4, 16.1, 20.1, 20.2, 20.3, 20.4, 20.5_


- [ ] 5.4 Implement Commitment Key Management
  - Implement generate_commitment_key(K, T, d) computing key size d·K^{1/d}·T
  - For HyperKZG:
    * Generate powers-of-tau SRS of size d·K^{1/d}·T
    * Store as Vec<G1Point>
    * Support trusted setup ceremony
  - For Dory:
    * Generate commitment key of size 2·√(K·T) group elements
    * Split between G1 and G2
    * Transparent setup (no trusted setup)
  - Implement commitment size batching:
    * Trade k-fold SRS reduction for k group elements per commitment
    * commitment_size = k, SRS_size = original_size / k
    * Example: k=32 reduces SRS from 2^26 to 2^21
  - Add parameter selection logic:
    * d=1 for K ≤ 2^16
    * d=2 for K ≤ 2^20
    * d=4 for K ≤ 2^30
    * d=8 for K > 2^30
  - Add tests for various (K,T,d) configurations
  - _Requirements: 11A.16, 11A.17, 21.1, 21.2, 21.3, 21.4, 33A.6, 33A.7, 33A.8_

## Phase 6: Jolt-Style zkVM Integration

- [x] 6.1 Implement zkVM Core Architecture
  - Create LatticeJoltZkVM<K,R,PCS> with num_registers: 32, ram_size, cycles_per_shard: 2^20, fetch_shout, exec_shout, register_twist, ram_twist, constraint_checker
  - Implement new_riscv(ram_size, pcs) initializing for RISC-V
  - Configure Shout instances:
    * fetch_shout: K=2^20 (program size), T=2^20 (cycles), d=1
    * exec_shout: K=2^16 (instruction tables), T=2^20, d=1
  - Configure Twist instances:
    * register_twist: K=32 (registers), T=2^20, d=1
    * ram_twist: K=ram_size, T=2^20, d=4 (for large RAM)
  - Initialize constraint checker (Spartan-style)
  - Add tests initializing zkVM
  - _Requirements: 17A.1, 17A.2, 22.1, 22.2, 22.3, 22.4, 22.5_

- [x] 6.2 Implement Single Cycle Proving
  - Implement prove_cycle(cycle, instruction, register_reads, register_write)
  - Step 1 - Fetch: Prove instruction fetch via Shout
    * Lookup instruction at program_counter
    * fetch_proof = fetch_shout.prove_lookup(cycle, instruction.address)
  - Step 2 - Decode/Execute: Prove instruction execution via Shout
    * Decompose instruction for lookup tables
    * exec_proof = exec_shout.prove_batch_evaluation(&instruction.decompose())
  - Step 3 - Register Reads: Prove via Twist
    * For each source register: prove_read(cycle, register)
    * read_proofs = [register_twist.prove_read(cycle, ra1), register_twist.prove_read(cycle, ra2)]
  - Step 4 - Register Write: Prove via Twist
    * write_proof = register_twist.prove_write(cycle, register_write, result)
  - Step 5 - RAM Access: Prove via Twist (if load/store)
    * If instruction.is_memory_op(): ram_proof = ram_twist.prove_memory_op(cycle, address, is_load)
  - Return CycleProof{fetch_proof, exec_proof, read_proofs, write_proof, ram_proof}
  - Add tests for various RISC-V instructions
  - _Requirements: 17A.3, 17A.4, 17A.5, 17A.6, 17A.7, 23.1, 23.2, 23.3, 23.4, 23.5, 23.6_


- [x] 6.3 Implement Shard Proving
  - Implement prove_shard(start_cycle, instructions) proving multiple cycles
  - Algorithm:
    * For each instruction: cycle_proof = prove_cycle(start_cycle + offset, instruction, ...)
    * Collect all cycle_proofs
    * Batch proofs: batched = batch_cycle_proofs(cycle_proofs)
    * Apply constraint checking: verify VM transition constraints
    * Apply Symphony folding: folded = apply_symphony_folding(batched)
    * Return ShardProof
  - Implement batch_cycle_proofs combining proofs efficiently
  - Implement constraint checking for VM transitions:
    * Verify program counter updates correctly
    * Verify register updates follow instruction semantics
    * Verify ~20 constraints per cycle
  - Verify shard size: 2^20 cycles (1M cycles)
  - Add tests with small programs (10-100 cycles)
  - _Requirements: 18.14, 18.15, 18.16, 18.17, 24.1, 24.2, 24.3, 24.4_

- [x] 6.4 Implement Instruction Execution Tables
  - Create lookup tables for primitive RISC-V instructions
  - Implement MLE-structured tables:
    * Table size K = 2^16 for most instructions
    * Structured so verifier can evaluate at random point in O(log K) time
  - Support decomposable tables for complex instructions:
    * Split 64-bit operation into 4×16-bit lookups
    * Use Lasso-style decomposition
    * Combine results via Shout batch evaluation
  - Implement table construction:
    * For ADD: table[a,b] = a + b mod 2^64
    * For XOR: table[a,b] = a ⊕ b
    * For MUL: table[a,b] = a × b mod 2^64
    * etc. for all RISC-V instructions
  - Integrate with Shout for batch evaluation
  - Add tests verifying table correctness
  - _Requirements: 17A.6, 18.18, 18.19, 25.1, 25.2, 25.3, 25.4_

## Phase 7: Symphony High-Arity Folding Integration

- [x] 7.1 Implement CCS Conversion for Twist and Shout
  - Create SymphonyTwistShoutFolder<K,R> with num_instances: ℓ_np, beta: Vec<K>, folded_instance
  - Implement shout_to_ccs(shout: &ShoutInstance) converting to CCS
  - Algorithm:
    * Extract constraint matrices M_0, ..., M_{d-1}
    * For d=1: rank-1 constraint ra(k,j)·Val(k) = rv(j)
    * For d>1: rank-d constraint Π_ℓ ra_ℓ(k_ℓ,j)·Val(k) = rv(j)
    * Build matrices encoding these constraints
    * Return CCSInstance{matrices, witness, public_input}
  - Implement twist_to_ccs(twist: &TwistInstance) converting to CCS
  - Algorithm:
    * Extract constraints for read-checking, write-checking
    * Build matrices for Inc(k,j) = wa(k,j)·(wv(j) - Val(k,j))
    * Return CCSInstance
  - Add tests verifying CCS correctness
  - _Requirements: 18A.4, 18A.5, 26.1, 26.2, 26.3, 26.4_


- [x] 7.2 Implement Parallel Π_gr1cs Folding
  - Implement fold_shout_instances(instances: Vec<ShoutInstance>) folding ℓ_np Shout instances
  - Algorithm:
    * Convert each to CCS: ccs_instances = instances.map(shout_to_ccs)
    * Sample shared randomness: β ← S^{ℓ_np} where ∥S∥_op ≤ 15
    * For each CCS instance: claim_i = compute_gr1cs_claim(ccs_i, β_i)
    * Collect 2ℓ_np claims (2 per instance)
    * Merge claims: final_claims = merge_claims(&claims)
    * Convert to tensor-of-rings: folded = claims_to_tensor_of_rings(final_claims)
    * Return FoldedInstance
  - Implement fold_twist_instances similarly
  - Implement compute_gr1cs_claim(ccs, β) computing grand R1CS claim
  - Verify parallel processing: all instances use same randomness
  - Add tests with ℓ_np = 2^10, 2^12, 2^16
  - _Requirements: 18A.6, 18A.7, 27.1, 27.2, 27.3, 27.4_

- [x] 7.3 Implement Claim Merging via Random Linear Combination
  - Implement merge_claims(claims: &[K]) merging 2ℓ_np claims into 2
  - Algorithm:
    * Sample random coefficients: γ_1, ..., γ_{ℓ_np} ← F
    * Compute merged_claim_1 = Σ_i γ_i·claims[2i]
    * Compute merged_claim_2 = Σ_i γ_i·claims[2i+1]
    * Return [merged_claim_1, merged_claim_2]
  - Implement claims_to_tensor_of_rings(claims) converting to lattice representation
  - Algorithm:
    * For each claim (K-element): convert to TensorOfRings<K,R>
    * Use as_rq_module() for folding operations
    * Return Vec<TensorOfRings>
  - Verify soundness: merged claims imply all original claims
  - Add tests verifying claim correctness
  - _Requirements: 18A.8, 18A.9, 28.1, 28.2, 28.3, 28.4_

- [x] 7.4 Implement Batch Folding
  - Implement batch_fold(num_instances: ℓ_np) folding many instances together
  - Configure ℓ_np ∈ {2^10, 2^12, 2^14, 2^16}
  - Algorithm:
    * Collect ℓ_np Twist/Shout instances
    * Apply parallel Π_gr1cs with shared randomness
    * Merge 2ℓ_np claims into 2
    * Convert to single folded instance
    * Compress proof size
  - Measure compression ratio: many proofs → single proof
  - Verify soundness maintained through folding
  - Add end-to-end tests
  - _Requirements: 18A.10, 29.1, 29.2, 29.3_


## Phase 8: Optimizations and Performance

- [x] 8.1 Implement Gruen's Sum-Check Optimization
  - Modify DenseSumCheckProver to compute s'_i instead of s_i
  - Algorithm for round i:
    * Define s'_i(c) = A·C(c) where A = Π_{j=1}^{i-1} eq_factor(r_j)
    * C(c) = Σ_{x'} p̃(r_1,...,r_{i-1},c,x')·q̃(r_1,...,r_{i-1},c,x')
    * Leave out B(c) = (r_i·c + (1-r_i)·(1-c)) from s'_i
    * Compute s'_i at d+1 points (degree d instead of d+1)
    * Derive s_i(c) = s'_i(c)·B(c) in O(d) time
  - Verify degree reduction: s'_i has degree d, s_i has degree d+1
  - Prover saves one evaluation per round
  - Total savings: n evaluations over n rounds
  - Add tests comparing with/without optimization
  - _Requirements: 18C.17, 18C.18, 18C.19, 30.1, 30.2, 30.3, 30.4_

- [x] 8.2 Implement Parallel Sum-Check Proving
  - Parallelize array updates within sum-check rounds
  - Algorithm:
    * Split array into chunks (one per core)
    * Process each chunk independently: new_p[j] = (1-r)·p[j] + r·p[j+half]
    * No synchronization needed within round
    * Synchronize only between rounds
  - Implement work stealing for load balancing:
    * If core finishes early, steal work from busy cores
    * Use lock-free work queue
  - Distribute work across multiple cores:
    * Use rayon for parallel iterators
    * Minimize synchronization points
  - Measure speedup vs single-threaded
  - Add tests with 1,2,4,8,16 cores
  - _Requirements: 29.1, 29.2, 29.3, 29.4, 31.1, 31.2, 31.3, 31.4_

- [x] 8.3 Implement Streaming Prover with Controlled Memory
  - Implement streaming algorithm with O(N^{1/c}) memory
  - Configure c parameter (c=2 for O(√N), c=4 for O(N^{1/4}))
  - Algorithm for c=2:
    * Stage 1: Process first n/2 variables with O(√N) memory
    * Make one streaming pass over non-zero terms
    * Stage 2: Process last n/2 variables with O(√N) memory
    * Make another streaming pass
  - Avoid materializing full K·T arrays:
    * Process data in chunks
    * Keep only current chunk in memory
    * Stream from disk if necessary
  - Measure peak memory usage
  - Add tests with N=2^20, c=2,3,4
  - _Requirements: 30.1, 30.2, 30.3, 30.4, 32.1, 32.2, 32.3, 32.4_


- [x] 8.4 Optimize for Cache Locality
  - Structure data for sequential access:
    * Store arrays contiguously in memory
    * Process in order to maximize cache hits
    * Avoid random access patterns
  - Minimize cache misses in hot loops:
    * Prefetch next chunk while processing current
    * Use cache-oblivious algorithms where possible
    * Profile cache miss rates
  - Use SIMD instructions where applicable:
    * Vectorize field additions: process 4-8 elements at once
    * Vectorize field multiplications where supported
    * Use platform-specific intrinsics (AVX2, AVX-512)
  - Profile memory access patterns:
    * Use perf/vtune to identify bottlenecks
    * Measure L1/L2/L3 cache hit rates
    * Optimize hot paths
  - Add benchmarks measuring cache performance
  - _Requirements: 23.8, 23.9, 23.13, 29.7, 33.1, 33.2, 33.3, 33.4_

## Phase 9: Testing and Validation

- [ ] 9.1 Unit Tests for Mathematical Primitives
  - Test multilinear extension correctness:
    * Verify MLE agrees with function on {0,1}^n
    * Test evaluate() matches direct computation
    * Test partial_eval() correctness
  - Test equality polynomial computation:
    * Verify eq(r,x) = 1 when r=x on Boolean hypercube
    * Test multilinearity in r
    * Test product formula
  - Test tensor-of-rings conversions:
    * Verify as_k_vector() ↔ as_rq_module() bijection
    * Test scalar multiplications
    * Test conversion preserves values
  - Add property-based tests with quickcheck
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 34.1, 34.2, 34.3, 34.4_

- [ ] 9.2 Unit Tests for Sum-Check Protocol
  - Test dense sum-check completeness:
    * Honest prover always accepted
    * Verify final evaluation correct
    * Test with various polynomial sizes
  - Test dense sum-check soundness:
    * Cheating prover rejected with high probability
    * Test soundness error bound: 2n/|F|
    * Verify verifier checks all rounds
  - Test sparse sum-check with various sparsities:
    * T=100, N=10^6 (very sparse)
    * T=10^4, N=10^6 (moderately sparse)
    * T=10^5, N=10^6 (less sparse)
  - Test prefix-suffix algorithm:
    * Verify O(T + √N) prover time for c=2
    * Test stage transitions
    * Verify correctness
  - _Requirements: 2.1, 2.2, 2.3, 4.1, 4.2, 35.1, 35.2, 35.3, 35.4_


- [ ] 9.3 Unit Tests for One-Hot Encoding
  - Test tensor product decomposition:
    * Verify encode() produces valid one-hot vectors
    * Test to_full_vector() reconstruction
    * Verify single 1 at correct position
  - Test Booleanity checks:
    * Verify rejection of non-Boolean values
    * Test with various invalid inputs
    * Measure soundness error
  - Test Hamming-weight-one checks:
    * Verify rejection of multiple 1s
    * Verify rejection of all 0s
    * Test both field types (binary and non-binary)
  - Test address reconstruction:
    * Verify raf conversion correct
    * Test with various (K,d) configurations
    * Verify bijection between one-hot and field element
  - _Requirements: 11A.1, 11A.2, 11A.3, 11A.12, 36.1, 36.2, 36.3, 36.4_

- [ ] 9.4 Integration Tests for Shout
  - Test read-checking sum-check:
    * Prove T lookups into table of size K
    * Verify all lookups correct
    * Test with K=256, T=100; K=2^16, T=2^10
  - Test virtual read values:
    * Verify rv computed correctly via sum-check
    * Compare to explicit commitment
    * Measure commitment cost savings
  - Test with various memory sizes and d values:
    * (K=32, d=1), (K=1024, d=2), (K=2^20, d=4)
    * Verify correctness for each configuration
    * Measure performance scaling
  - Test sparse-dense protocol for large tables:
    * K=2^20, T=2^10, C=2
    * K=2^64, T=2^16, C=4 (structured table)
    * Verify O(C·T) prover time
  - _Requirements: 9.1, 9.12, 9.34, 9.35, 37.1, 37.2, 37.3, 37.4_

- [ ] 9.5 Integration Tests for Twist
  - Test increment computation:
    * Verify Inc(k,j) = wa(k,j)·(wv(j) - Val(k,j))
    * Test with various write patterns
    * Verify only T non-zero increments
  - Test Val-evaluation sum-check:
    * Verify Val(raddress,rcycle) computed correctly
    * Test increment aggregation
    * Verify less-than predicate
  - Test locality-aware prover:
    * Compare local vs random access patterns
    * Measure O(i) cost for 2^i-local accesses
    * Verify speedup for local accesses
  - Test less-than predicate:
    * Verify LT(j',j) = 1 iff j' < j
    * Test verifier O(log T) evaluation
    * Test with various (j',j) pairs
  - _Requirements: 11.17, 11.21, 11.31, 11.32, 38.1, 38.2, 38.3, 38.4_


- [ ] 9.6 End-to-End zkVM Tests
  - Test single RISC-V instruction execution:
    * ADD: test register addition
    * XOR: test bitwise XOR
    * LOAD: test RAM read
    * STORE: test RAM write
    * Verify all proofs valid
  - Test register reads and writes:
    * Prove 2 register reads per cycle
    * Prove 1 register write per cycle
    * Verify register values correct
  - Test RAM access for load/store:
    * Prove RAM read for LOAD instruction
    * Prove RAM write for STORE instruction
    * Verify memory consistency
  - Test complete program execution:
    * Simple program: add two numbers
    * Loop program: sum array
    * Recursive program: factorial
    * Verify end-to-end correctness
  - Test with real RISC-V binaries:
    * Compile C program to RISC-V
    * Execute in zkVM
    * Generate and verify proof
    * Measure prover performance
  - _Requirements: 18.1, 18.2, 18.3, 18.4, 39.1, 39.2, 39.3, 39.4, 39.5_

## Phase 10: Benchmarking and Performance Analysis

- [ ]* 10.1 Implement Performance Benchmarks
  - Benchmark field operations per cycle:
    * Measure field additions, multiplications
    * Count operations in sum-check rounds
    * Compare to theoretical estimates
  - Benchmark lattice operations per cycle:
    * Measure group operations (MSMs)
    * Count commitment operations
    * Measure evaluation proof generation
  - Benchmark memory usage:
    * Track peak memory consumption
    * Measure memory per cycle
    * Verify O(N^{1/c}) for streaming
  - Benchmark proof generation time:
    * Measure wall-clock time per cycle
    * Measure time per shard (2^20 cycles)
    * Measure total time for program
  - Benchmark verification time:
    * Measure verifier time per proof
    * Verify O(log K + log T) scaling
    * Compare to baselines
  - _Requirements: 33.1, 33.2, 33.3, 33.4, 33.5, 40.1, 40.2, 40.3, 40.4, 40.5_


- [ ] 10.2 Compare to Baseline Implementations
  - Benchmark against Spice for registers:
    * Measure Spice: 40T + 40K field ops, 5 commitments per read
    * Measure Twist: O(K + T) field ops, d commitments per read
    * Calculate speedup factor
    * Verify 10-20× improvement
  - Benchmark against Lasso for lookups:
    * Measure Lasso: 12T + 12K field ops, 3T + K commitments
    * Measure Shout: O(K + T) field ops, d·T commitments
    * Calculate speedup factor
    * Verify 10× improvement for log proofs
  - Benchmark against LogUpGKR:
    * Measure LogUpGKR: 24T + 24K field ops, 2T + K commitments
    * Measure Shout performance
    * Calculate speedup factor
  - Measure speedup factors:
    * Field operations speedup
    * Commitment cost speedup
    * Total prover time speedup
  - Validate 10-20× improvements:
    * For logarithmic proof length
    * For small memories (K=32)
    * For medium memories (K=2^20)
  - Add comparison tables and graphs
  - _Requirements: 11D.6, 11D.7, 11D.19, 11D.20, 33B.1, 41.1, 41.2, 41.3, 41.4, 41.5_

- [ ] 10.3 Analyze Soundness Error
  - Compute total soundness error:
    * Sum errors from all sum-check invocations
    * Booleanity check: (log K + log T)/|F|
    * One-hot check: log T/|F|
    * Read-checking: (2 log K + log T)/|F|
    * Write-checking: (log K + log T)/|F|
    * Val-evaluation: log T/|F|
    * Total: ~(5 log K + 5 log T)/|F|
  - Verify log(K·T)/|F| bound:
    * For K=32, T=2^20: ~45/2^128 ≈ 2^{-122}
    * For K=2^20, T=2^20: ~80/2^128 ≈ 2^{-121}
  - Compare to offline memory checking:
    * Offline: (K+T)/|F| ≈ 2^20/2^128 = 2^{-108}
    * Twist/Shout: log(K·T)/|F| ≈ 40/2^128 = 2^{-122}
    * Improvement: 14 bits of security
  - Validate security levels:
    * 128-bit security: ensure error ≤ 2^{-128}
    * Field size selection: |F| ≥ 2^128 for 128-bit security
    * Extension field: use t=2 for 256-bit field from 128-bit base
  - _Requirements: 18B.1, 18B.2, 18B.9, 18B.10, 42.1, 42.2, 42.3, 42.4_


- [ ] 10.4 Profile and Optimize Hot Paths
  - Profile prover execution:
    * Use perf/vtune/flamegraph
    * Identify functions consuming most time
    * Measure time per function
  - Identify bottlenecks:
    * Field arithmetic operations
    * Array updates in sum-check
    * Commitment computations
    * Memory access patterns
  - Optimize critical loops:
    * Unroll loops where beneficial
    * Vectorize with SIMD
    * Reduce branches in hot paths
    * Inline small functions
  - Measure improvement after optimization:
    * Before/after comparison
    * Speedup per optimization
    * Total cumulative speedup
  - Iterate until performance targets met:
    * Target: 500 field muls per cycle
    * Target: 2 lattice ops per cycle
    * Target: 1 MHz prover throughput
  - _Requirements: 23.19, 33.4, 43.1, 43.2, 43.3, 43.4_

## Phase 11: Fast-Prover SNARKs for Non-Uniform Computation

- [x] 11.1 Implement SpeedySpartan for Plonkish Constraints
  - Create SpeedySpartan<K,PCS> struct for Plonkish constraint systems
  - Implement gate output table construction:
    * Table size n (number of gates)
    * Store output of each gate
    * Create MLE of gate outputs
  - Use Shout for gate input lookups:
    * Each gate has 2 inputs
    * Lookup inputs in gate output table
    * Prove lookups via Shout
  - Implement virtual polynomials for gate wires:
    * Wire values not committed
    * Computed via lookups into output table
    * Reduces commitment costs 4×
  - Achieve 4× reduction vs BabySpartan:
    * BabySpartan commits to wire values
    * SpeedySpartan uses virtual polynomials
    * Only commit to gate outputs
  - Add tests with various circuit sizes
  - _Requirements: 18A.1, 18A.2, 18A.8, 18A.16, 18A.26, 44.1, 44.2, 44.3, 44.4, 44.5_

- [x] 11.2 Implement Spartan++ for CCS Constraints
  - Create SpartanPlusPlus<K,PCS> struct for CCS (Customizable Constraint Systems)
  - Improve Spark sparse polynomial commitment:
    * Spark commits to sparse polynomial indices
    * Evaluation requires lookups into Lagrange basis table
    * Table size n² (all basis evaluations at random point)
  - Use Shout for Lagrange basis lookups:
    * Replace Lasso with Shout
    * Lookup basis evaluations
    * Batch multiple lookups
  - Implement virtual polynomials for lookup results:
    * Lookup results not committed
    * Computed via Shout
    * Eliminates major Spark bottleneck
  - Achieve 6× improvement vs original Spartan:
    * Faster sparse polynomial evaluation proofs
    * Reduced commitment costs
    * Better field operation count
  - Add tests with various constraint systems
  - _Requirements: 18A.4, 18A.9, 18A.18, 18A.19, 18A.20, 45.1, 45.2, 45.3, 45.4, 45.5_


- [x] 11.3 Integrate with Circuit Compilers
  - Support Plonkish constraint systems:
    * Parse Plonkish circuit description
    * Extract gates and wiring
    * Build gate output table
    * Generate SpeedySpartan proof
  - Support R1CS constraint systems:
    * Parse R1CS: (A·z) ◦ (B·z) = C·z
    * Convert to CCS format
    * Generate Spartan++ proof
  - Support CCS (Customizable Constraint Systems):
    * Parse CCS: Σ_i c_i · ◦_{j∈S_i} M_j·z = 0
    * Handle arbitrary constraint patterns
    * Generate Spartan++ proof
  - Implement constraint system conversions:
    * R1CS → CCS
    * Plonkish → CCS
    * Optimize conversion for common patterns
  - Add tests with circuits from various compilers
  - _Requirements: 18A.21, 18A.22, 18A.23, 46.1, 46.2, 46.3, 46.4_

## Phase 12: Parameter Selection and Deployment

- [x] 12.1 Implement Parameter Selection Logic
  - Create parameter_selection(K, T, commitment_scheme) returning optimal d
  - For K=32 (RISC-V registers):
    * d=1: 32 values per address
    * Commitment key: 32·T group elements
    * Optimal for small memory
  - For K=2^20 (4MB RAM):
    * d=4: 4·32 = 128 values per address
    * Commitment key: 128·T group elements
    * Balance between key size and committed 1s
  - For gigantic tables (K=2^64):
    * Use sparse-dense sum-check
    * d=8 or higher
    * Structured table evaluation
  - Balance commitment costs, prover time, and proof size:
    * Small d: fewer committed 1s, larger key
    * Large d: more committed 1s, smaller key
    * Proof size grows linearly with d
  - Add parameter selection tests
  - _Requirements: 33A.1, 33A.2, 33A.3, 33A.4, 33A.5, 47.1, 47.2, 47.3, 47.4, 47.5_

- [x] 12.2 Implement Commitment Scheme Selection
  - Support HyperKZG for elliptic curve commitments:
    * Single group element commitment
    * O(log n) evaluation proof
    * Requires trusted setup (powers-of-tau)
    * Fast for small values and sparsity
  - Support Dory for transparent commitments:
    * √n commitment key size
    * O(log n) verification time
    * No trusted setup
    * Good for sparse vectors
  - Support Binius/FRI-Binius for binary fields:
    * Hashing-based commitment
    * Small commitment key
    * Post-quantum secure
    * Requires packing optimization
  - Implement packing for binary field schemes:
    * Pack 128 values into single GF(2^128) element
    * Commit to packed values
    * 128× reduction in committed elements
  - Add tests for each commitment scheme
  - _Requirements: 33A.11, 33A.12, 33A.13, 48.1, 48.2, 48.3, 48.4_


- [x] 12.3 Implement Sharding and Recursion
  - Break execution into shards of 2^20 cycles:
    * Each shard: 1M cycles
    * Prove each shard independently
    * Bounded prover memory per shard
  - Prove each shard semi-independently:
    * Shard i depends only on final state of shard i-1
    * Parallel proving of multiple shards
    * Aggregate shard proofs
  - Implement SNARK composition for proof shrinking:
    * Generate proof π_i for shard i
    * Generate proof π_comp that π_i is valid
    * Recursively compress proofs
  - Support cycle of curves for recursion:
    * Use Pasta curves (Pallas/Vesta)
    * Alternate between curves for recursion
    * Maintain efficient field arithmetic
  - Add tests with multi-shard programs
  - _Requirements: 33A.18, 33A.19, 33A.20, 33A.21, 49.1, 49.2, 49.3, 49.4_

- [x] 12.4 Production Hardening
  - Add comprehensive error handling:
    * Define TwistShoutError enum
    * Handle all error cases gracefully
    * Provide informative error messages
  - Implement logging and diagnostics:
    * Log prover progress
    * Track performance metrics
    * Debug mode with detailed output
  - Add security auditing hooks:
    * Validate all inputs
    * Check soundness conditions
    * Detect potential attacks
  - Create deployment documentation:
    * Installation guide
    * Configuration guide
    * Performance tuning guide
    * Troubleshooting guide
  - Implement configuration management:
    * TOML/YAML config files
    * Environment variables
    * Command-line arguments
    * Sensible defaults
  - _Requirements: 27.1, 27.2, 27.3, 50.1, 50.2, 50.3, 50.4, 50.5_

## Phase 13: Documentation and Examples

- [ ]* 13.1 Create API Documentation
  - Document all public interfaces:
    * Rustdoc comments for all public items
    * Module-level documentation
    * Crate-level overview
  - Add usage examples for each component:
    * Extension field arithmetic
    * Multilinear polynomials
    * Sum-check protocol
    * Shout protocol
    * Twist protocol
  - Create architecture diagrams:
    * System overview
    * Component interactions
    * Data flow diagrams
    * Protocol sequence diagrams
  - Document performance characteristics:
    * Complexity analysis
    * Benchmark results
    * Comparison tables
    * Optimization guidelines
  - _Requirements: 33.17, 33.18, 51.1, 51.2, 51.3, 51.4_


- [ ] 13.2 Create Tutorial Examples
  - Example: Simple sum-check protocol
    * Prove sum of polynomial evaluations
    * Step-by-step walkthrough
    * Explain each round
    * Show verifier checks
  - Example: Shout for small lookup table
    * Table size K=16, T=10 lookups
    * Show one-hot encoding
    * Show commitment phase
    * Show proof generation
    * Show verification
  - Example: Twist for register file
    * 32 registers, 100 cycles
    * Show increment computation
    * Show read/write proofs
    * Show locality benefits
  - Example: Complete zkVM cycle
    * Single RISC-V ADD instruction
    * Show all proof components
    * Explain integration
  - Example: End-to-end RISC-V program proof
    * Simple C program
    * Compile to RISC-V
    * Generate proof
    * Verify proof
    * Measure performance
  - _Requirements: 52.1, 52.2, 52.3, 52.4, 52.5_

- [x] 13.3 Create Performance Guide
  - Document parameter selection guidelines:
    * How to choose d for given K
    * When to use Shout vs Lasso
    * When to use Twist vs Spice
    * Commitment scheme selection
  - Document optimization techniques:
    * Gruen's optimization
    * Parallel proving
    * Streaming proving
    * Cache optimization
    * SIMD vectorization
  - Document benchmarking methodology:
    * How to measure field operations
    * How to measure lattice operations
    * How to measure memory usage
    * How to measure wall-clock time
  - Document comparison to baselines:
    * Spice comparison methodology
    * Lasso comparison methodology
    * LogUpGKR comparison methodology
    * Interpretation of results
  - _Requirements: 53.1, 53.2, 53.3, 53.4_

## Summary and Milestones

**Total: 13 Phases, 53 Major Tasks, 200+ Detailed Subtasks**

**Phase Breakdown:**
- Phase 1-2 (Weeks 1-4): Core primitives, sum-check, Shout - 12 tasks
- Phase 3-4 (Weeks 5-8): Twist, virtual polynomials - 11 tasks
- Phase 5-6 (Weeks 9-12): Lattice integration, zkVM - 10 tasks
- Phase 7-8 (Weeks 13-14): Symphony folding, optimizations - 8 tasks
- Phase 9-10 (Weeks 15-16): Testing, benchmarking - 10 tasks
- Phase 11-13 (Ongoing): Advanced features, documentation - 12 tasks

**Key Milestones:**
- Week 4: Working Shout protocol with tests, achieving O(K+T) prover time
- Week 8: Working Twist protocol with locality-aware optimization
- Week 12: Complete zkVM proving RISC-V execution end-to-end
- Week 14: Symphony folding compressing 2^10-2^16 instances
- Week 16: Production-ready with 10-20× speedup vs baselines validated

**Performance Targets:**
- Prover: ~500 field multiplications per cycle
- Prover: ~2 lattice operations per cycle
- Throughput: 1 MHz (1M cycles/second) on commodity hardware
- Proof size: <200KB post-quantum, <50KB classical
- Verification: Tens of milliseconds
- Soundness: >120 bits of security

**Dependencies:**
- Phases 1-2 must complete before Phase 3
- Phase 5 requires existing HyperWolf PCS implementation
- Phase 6 requires Phases 1-5 complete
- Phase 7 requires existing Symphony implementation
- Phases 9-10 can run in parallel with development
- Phases 11-13 can be done incrementally

**Success Criteria:**
- All tests passing
- 10-20× speedup vs Spice/Lasso validated
- End-to-end zkVM working with real RISC-V binaries
- Performance targets met
- Documentation complete
- Production-ready code quality

