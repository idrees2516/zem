# Requirements Document: Lookup Table Arguments Implementation

## Introduction

This document specifies the requirements for implementing a comprehensive lookup table arguments system based on the SoK paper "Lookup Table Arguments" (2025-1876). Lookup arguments are cryptographic protocols that enable efficient enforcement of non-native operations in zero-knowledge proof systems by proving that witness elements belong to predefined tables. This implementation will support multiple lookup variants, techniques, and composition strategies to enable practical applications in zkVMs, stateful computations, and constraint systems.

## Glossary

- **Lookup Argument**: A proof system that allows a prover to demonstrate that each element of a witness vector belongs to a predefined lookup table
- **Witness Vector (w)**: An ordered collection of n elements w ∈ S^n that the prover claims are contained in the table
- **Lookup Table (t)**: A predefined vector of N elements t ∈ S^N against which witness elements are checked
- **Multiset Equality**: A technique for proving lookup relations by reducing subset inclusion to multiset equality checks
- **Logup Lemma**: A technique that reformulates lookup inclusion as a rational function identity using logarithmic derivatives
- **Subvector Extraction**: A matrix-vector multiplication technique where lookup is expressed as M × t = w with elementary matrix M
- **Accumulator-Based**: Techniques using cryptographic accumulators that support batch commit-and-prove openings
- **Projective Lookup**: A generalization where only specific indices of the witness are checked against the table
- **Indexed Lookup**: A lookup where both witness and table are ordered, and the verifier receives commitments to indices
- **Vector Lookup**: A lookup where each table entry is a tuple of elements rather than a single element
- **Online Lookup Table**: A table that depends on the witness and cannot be preprocessed
- **Decomposable Table**: A table that can be decomposed into smaller subtables to improve prover efficiency
- **Polynomial Commitment Scheme (PCS)**: A cryptographic primitive enabling succinct commitment to polynomials with efficient opening proofs
- **PIOP (Polynomial Interactive Oracle Proof)**: An interactive proof system where the prover sends oracle polynomials
- **Commit-and-Prove SNARK**: A proof system where the instance contains commitments to (parts of) the witness
- **Preprocessing PIOP**: A PIOP with offline and online phases, where preprocessing generates auxiliary polynomials
- **Sumcheck Protocol**: An interactive protocol for verifying polynomial summations over Boolean hypercubes
- **Multilinear Extension (MLE)**: The unique multilinear polynomial extending a function from Boolean hypercube to field
- **KZG Commitment**: A pairing-based polynomial commitment scheme with homomorphic properties
- **GKR Protocol**: An argument of knowledge for layered arithmetic circuits
- **Accumulation Scheme**: A protocol reducing satisfiability of two NP statements into a single accumulated statement
- **IVC (Incremental Verifiable Computation)**: An argument system for proving iterative computations
- **Special-Sound Protocol**: An interactive protocol admitting a special-sound extractor
- **Table-Efficient**: Prover runtime sublinear in table size
- **Super-Sublinear**: Prover runtime independent of table size
- **Homomorphic Proof**: A proof system supporting aggregation of multiple proofs


## Requirements

### Requirement 1: Core Lookup Relation Definition

**User Story:** As a cryptographic protocol designer, I want to define and implement the fundamental lookup relation, so that I can build various lookup argument schemes on top of this foundation.

#### Acceptance Criteria

1. WHEN defining a lookup index I := (S, n, t), THE System SHALL represent S as a finite set, n as the number of lookups, and t ∈ S^N as the table vector
2. THE System SHALL define the lookup relation LK_I as the set of tuples w ∈ S^n such that w_i ∈ t for all i ∈ [n]
3. THE System SHALL validate that an index is valid if and only if 0 < n, 0 < N, and t ∈ S^N
4. THE System SHALL extend the subset relation A ⊆ B to apply to multisets
5. THE System SHALL treat both table t and witness w as ordered vectors rather than unordered sets

### Requirement 2: Committed Lookup Relation

**User Story:** As a proof system developer, I want to implement committed lookup relations, so that I can compose lookup arguments with other proof systems at the argument level.

#### Acceptance Criteria

1. GIVEN a lookup index I := (S, n, t) and commitment scheme C = (Com, Open) on S^n, THE System SHALL define CLK_{I,C} as {(c; w) : w ∈ LK_I, c = Com(w)}
2. THE System SHALL support composition via the commit-and-prove paradigm where both lookup and main proof system share commitments to the same witness
3. THE System SHALL ensure the commitment scheme C provides binding and hiding properties as required
4. THE System SHALL allow the verifier to receive only the commitment c without the plaintext witness w
5. THE System SHALL enable the prover to demonstrate knowledge of w such that c = Com(w) and w ∈ LK_I

### Requirement 3: Oracle Lookup Relation

**User Story:** As a PIOP designer, I want to implement oracle lookup relations, so that I can compose lookup proofs with other proof systems at the PIOP level.

#### Acceptance Criteria

1. GIVEN a lookup index I := (S, n, t), THE System SHALL define OLK_I as {([[w]]; w) : w ∈ LK_I}
2. THE System SHALL provide the verifier with oracle access [[w]] to the witness polynomial
3. THE System SHALL support sequential composition of PIOPs for lookup and main proof system
4. THE System SHALL enable compilation of composed PIOP into argument of knowledge by replacing oracles with polynomial commitments
5. THE System SHALL maintain information-theoretic security in the oracle model before compilation

### Requirement 4: Projective Lookup Relations

**User Story:** As a zkVM developer, I want to implement projective lookups, so that I can efficiently verify that only specific witness indices belong to a table without checking the entire witness.

#### Acceptance Criteria

1. GIVEN a projective lookup index I = ((S, n, t), m, i = {i_1, ..., i_n}), THE System SHALL define PLK_I as {w ∈ S^m : w_i ⊆ t}
2. THE System SHALL validate that the projective index satisfies 0 ≤ i_1 < ... < i_n < m
3. THE System SHALL define projective committed lookup relation as {(c; w) : w ∈ PLK_I, c = Com(w)}
4. THE System SHALL define projective oracle lookup relation as {([[w]]; w) : w ∈ PLK_I}
5. THE System SHALL support efficient projective lookups without explicitly constructing the subvector
6. THE System SHALL extend Logup lemma to projective setting using selector vector s where s_i ∈ {0,1}
7. THE System SHALL verify the projective Logup identity: Σ_{i∈[n]} s_i/(x + w_i) = Σ_{i∈[N]} m_i/(x + t_i)


### Requirement 5: Indexed Lookup Relations

**User Story:** As a Jolt zkVM implementer, I want to support indexed lookups, so that I can externally represent arbitrary functions via tables without encoding function logic in circuits.

#### Acceptance Criteria

1. GIVEN a lookup index I := (S, n, t), THE System SHALL define indexed lookup relation as set of tuples (w, i) where w ⊆ S, i ⊆ [N], |i| = |w| = n
2. THE System SHALL enforce that for all k ∈ [n], the entry w_k equals the table entry at index i_k, i.e., w_k = t_{i_k}
3. THE System SHALL provide the verifier with commitments to both witness w and index vector i
4. THE System SHALL support generic compiler from standard to indexed lookup when S = F and characteristic is large enough
5. THE System SHALL implement the encoding t*_i = i · r + t_i and a*_j = b_j · r + a_j where m · N < char(F)
6. THE System SHALL perform range check to ensure a_j ∈ [r] for each lookup
7. THE System SHALL support indexed lookup via vector lookups by treating table as vector of pairs (i, t_i)

### Requirement 6: Vector Lookup Relations

**User Story:** As a proof system architect, I want to implement vector lookups, so that I can efficiently handle tables where each entry is a tuple of elements.

#### Acceptance Criteria

1. GIVEN a vector lookup index I := (S, n, k, t) where t ∈ S^{(k)N}, THE System SHALL define vector lookup relation as {w ∈ S^{(k)n} : ∀i ∈ [n], w_i ∈ t}
2. THE System SHALL extend Logup lemma to vectorized form using polynomials w_i(y) := Σ_{j=1}^v w_{i,j} · y^{j-1}
3. THE System SHALL verify vectorized Logup identity: Σ_{i=1}^n 1/(x + w_i(y)) = Σ_{i=1}^N m_i/(x + t_i(y))
4. THE System SHALL support vector lookups from homomorphic proofs by aggregating k separate lookup proofs
5. THE System SHALL implement linearization technique transforming k-tuples into 3-tuples {(x_i, y_j, r_i)}_{i∈[k], j∈[N]}
6. THE System SHALL perform consistency checks ensuring linearized vector corresponds to concatenation of k-tuples
7. THE System SHALL verify that all x_i values are equal across each tuple

### Requirement 7: Online Lookup Tables

**User Story:** As a distributed proving system developer, I want to support online lookup tables, so that I can handle tables that depend on the witness and cannot be preprocessed.

#### Acceptance Criteria

1. GIVEN an online lookup index I := (S, n, N), THE System SHALL define online lookup relation as {(w, t) : w ⊆ t} where both w ∈ S^n and t ∈ S^N
2. THE System SHALL place the table t in the lookup instance rather than in the index
3. THE System SHALL support tables that depend on verifier challenges (e.g., eq(x, r) for random r)
4. THE System SHALL enable construction of online tables for mutual witness wires in distributed proving
5. THE System SHALL ensure compatibility with non-preprocessing schemes like Plookup and multiset equality techniques
6. THE System SHALL NOT require preprocessing phase for online tables

### Requirement 8: Decomposable Tables

**User Story:** As a Jolt implementer, I want to support decomposable tables, so that I can efficiently perform lookups in massive tables (e.g., size 2^128) that cannot be materialized.

#### Acceptance Criteria

1. GIVEN a table t ∈ S^N, THE System SHALL define decomposability into tables t_i ∈ S^{N_i} for 1 ≤ i ≤ k via map M: S → S_1 × ... × S_k
2. THE System SHALL verify that s ∈ t if and only if s_i ∈ t_i for all 1 ≤ i ≤ k where M(s) = (s_1, ..., s_k)
3. THE System SHALL extend decomposability to indexed tables using maps M_set: S → S_1 × ... × S_k and M_index: [N] → [N_1] × ... × [N_k]
4. THE System SHALL verify indexed decomposition: s = t[j] ⟺ s_i = t_i[j_i] for all 1 ≤ i ≤ k
5. THE System SHALL transform witness w via M_set into k vectors (w_1, ..., w_k) applied entry-wise
6. THE System SHALL prove lookup relation w_i ⊆ t_i for each subvector w_i with proof π_i
7. THE System SHALL prove correctness of decomposition ensuring commitments (C_1, ..., C_k) are consistent with C under M_set
8. THE System SHALL support linear decomposition maps enabling homomorphic verification (e.g., C = C_0 + 2^32 · C_1 + 2^64 · C_2 + 2^96 · C_3)
9. THE System SHALL verify decomposition for non-homomorphic PCS by checking w(r) = w_0(r) + 2^32 · w_1(r) + ... at random point r


### Requirement 9: Polynomial Commitment Scheme Interface

**User Story:** As a cryptographic library developer, I want to implement a generic polynomial commitment scheme interface, so that lookup arguments can be instantiated with different PCS backends.

#### Acceptance Criteria

1. THE System SHALL implement Setup(λ, k) algorithm outputting verifier key vk and prover key pk
2. THE System SHALL implement Commit(pk, p(X)) algorithm outputting commitment C
3. THE System SHALL implement Open(pk, p(X), x) algorithm outputting evaluation proof π for y = p(x)
4. THE System SHALL implement Verify(vk, C, x, π, y) algorithm outputting acceptance bit
5. THE System SHALL ensure completeness: honest prover always convinces verifier with probability 1
6. THE System SHALL ensure extractability: for all PPT adversaries A, there exists efficient extractor E such that Pr[Verify(vk, C, x, π, y) = 1 ∧ p(x) ≠ y] is negligible
7. THE System SHALL support univariate polynomials for KZG-based schemes
8. THE System SHALL support multilinear polynomials for Spartan/HyperPlonk-based schemes
9. THE System SHALL support multivariate polynomials for general schemes

### Requirement 10: Multiset Equality Technique (Plookup)

**User Story:** As a Plonk-based SNARK developer, I want to implement the Plookup multiset equality technique, so that I can add efficient lookup support to univariate polynomial-based proof systems.

#### Acceptance Criteria

1. THE System SHALL reduce subset inclusion w ⊆ t to multiset equality check: w ∪ t contains same elements as t with multiplicities
2. THE System SHALL ensure witness w is sorted relative to table t
3. THE System SHALL verify successive difference sets coincide: {w_2 - w_1, ..., w_n - w_{n-1}} = {t_2 - t_1, ..., t_N - t_{N-1}} ∪ {0}
4. THE System SHALL enforce sorting via permutation PIOP similar to Plonk permutation check
5. THE System SHALL construct PIOP using univariate polynomials compatible with any univariate PCS
6. THE System SHALL support small finite fields (e.g., p = 2^31 - 1) without requiring large characteristic
7. THE System SHALL achieve prover cost O((N + n) log(N + n)) field operations
8. THE System SHALL achieve verifier cost O(1) with constant proof size
9. THE System SHALL NOT require preprocessing beyond committing to table and witness

### Requirement 11: Multiset Equality Technique (Halo2)

**User Story:** As a Halo2 developer, I want to implement the Halo2 lookup technique, so that I can support lookups with offline memory checking approach.

#### Acceptance Criteria

1. THE System SHALL permute witness {w_i} into {w'_i} such that equal values are grouped and aligned with permuted table {t'_i}
2. THE System SHALL enforce local constraint: (w'_i - t'_i) · (w'_i - w'_{i-1}) = 0 for all i
3. THE System SHALL verify first factor zero implies w'_i matches table element
4. THE System SHALL verify second factor zero implies w'_i equals previous witness entry
5. THE System SHALL achieve prover cost O(N log N) field operations
6. THE System SHALL achieve verifier cost O(1) with constant proof size
7. THE System SHALL support univariate polynomial commitment schemes

### Requirement 12: Logup Lemma Foundation

**User Story:** As a STARK developer, I want to implement the Logup lemma, so that I can build efficient lookup arguments that work with non-homomorphic commitments and small fields.

#### Acceptance Criteria

1. GIVEN field F with characteristic p > max(n, N), THE System SHALL verify Logup identity: Σ_{i=1}^n 1/(x + w_i) = Σ_{i=1}^N m_i/(x + t_i)
2. THE System SHALL ensure existence of multiplicities {m_i}_{i=1}^N such that the identity holds
3. THE System SHALL derive Logup from polynomial identity: W(x) = ∏_{i∈[N]} (x + t_i)^{m_i}
4. THE System SHALL use logarithmic derivative equivalence: d/dx log g_1(x) = d/dx log g_2(x) ⟺ g_1(x) = g_2(x)
5. THE System SHALL support fields with characteristic p ≥ max(n, N) including BabyBear field (p = 2^31 - 1)
6. THE System SHALL NOT support binary fields (characteristic 2) due to characteristic constraint
7. THE System SHALL reduce lookup to verifying rational function summation equality


### Requirement 13: Logup+GKR Technique

**User Story:** As a hash-based SNARK developer, I want to implement Logup+GKR, so that I can achieve efficient lookups without requiring homomorphic commitments.

#### Acceptance Criteria

1. THE System SHALL apply GKR protocol to verify Logup equality holds
2. THE System SHALL construct layered arithmetic circuit receiving all numerators and denominators as inputs
3. THE System SHALL implement binary tree structure where each layer pairs and sums fractions, halving count per layer
4. THE System SHALL commit to lookup vector, table, and multiplicity vector
5. THE System SHALL require NO extra commitments beyond the three mentioned above
6. THE System SHALL achieve prover cost O(N + n) field operations
7. THE System SHALL achieve verifier cost O(log(N + n)) field operations
8. THE System SHALL support hash-based commitments (e.g., FRI-based)
9. THE System SHALL accept that circuit depends on table size N as limitation
10. THE System SHALL support compatibility with zkVMs like Stwo

### Requirement 14: cq (Cached Quotients) Technique

**User Story:** As a KZG-based proof system developer, I want to implement cq, so that I can achieve super-sublinear lookup arguments with O(n log n) prover time independent of table size.

#### Acceptance Criteria

1. THE System SHALL reduce lookup to Logup identity: Σ_{i∈[N]} m_i/(α + t_i) = Σ_{i∈[n]} 1/(α + w_i)
2. THE System SHALL interpolate left side over subgroup Ω_1 = {ω^i}_{i∈[N]} as polynomial p_1 of degree ≤ N where p_1(ω^i) = m_i/(α + t_i)
3. THE System SHALL interpolate right side over subgroup Ω_2 = {ω^i}_{i∈[n]} as polynomial p_2 of degree ≤ n where p_2(ω^i) = 1/(α + w_i)
4. THE System SHALL use KZG homomorphism to commit to both sides efficiently
5. THE System SHALL apply univariate sumcheck protocol to verify equality
6. THE System SHALL verify p_2 is well-formed: p_2(ω) = (α + w(ω))^{-1} for all ω ∈ Ω_2
7. THE System SHALL verify p_1 is well-formed by proving existence of quotient q(X): p_1(ω) · (t(ω) + α) - m(ω) = q(ω) · z_{Ω_1}(ω)
8. THE System SHALL preprocess commitments to cached quotients enabling O(n) computation of Com(q)
9. THE System SHALL achieve preprocessing cost O(N log N) group operations
10. THE System SHALL achieve prover cost O(n log n) field operations + 8n group operations
11. THE System SHALL achieve verifier cost 5 pairings with constant proof size
12. THE System SHALL support zero-knowledge variant with 8 G_1 elements proof size

### Requirement 15: cq Projective Extension

**User Story:** As a cq user, I want to support projective lookups in cq, so that I can efficiently verify only specific witness indices without overhead.

#### Acceptance Criteria

1. THE System SHALL replace p_2 interpolation with Σ_{i∈[n]} s_i/(x + w_i) where s is selector vector
2. THE System SHALL provide public polynomial s(X) interpolating selector vector s = {s_i}_{i∈[n]} on Ω_2
3. THE System SHALL verify p_2 well-formedness: s(ω) · (α + w(ω))^{-1} = p_2(ω) for all ω ∈ Ω_2
4. THE System SHALL maintain all other protocol steps unchanged
5. THE System SHALL incur additional cost of opening polynomial s(X) of degree n
6. THE System SHALL achieve same asymptotic complexity as standard cq

### Requirement 16: Multilinear cq (μ-seek)

**User Story:** As a HyperPlonk developer, I want to use cq with multilinear commitments, so that I can integrate table-efficient lookups with multilinear SNARKs.

#### Acceptance Criteria

1. THE System SHALL commit witness w using multilinear polynomial commitment scheme
2. THE System SHALL maintain left-hand side p_1 using KZG for cached quotients preprocessing
3. THE System SHALL verify p_2 well-formedness using multilinear polynomial checks
4. THE System SHALL use standard multilinear sumcheck for right-hand side
5. THE System SHALL use univariate sumcheck for left-hand side
6. THE System SHALL verify equality Σ_{ω∈Ω_1} p_1(ω) = Σ_{ω∈Ω_2} p_2(ω) combining both sumchecks
7. THE System SHALL enable compatibility with HyperPlonk and other multilinear SNARKs


### Requirement 17: cq Variants (cq+, cq++, zkcq+)

**User Story:** As a performance-focused developer, I want to implement cq variants, so that I can optimize for different trade-offs between proof size, verification cost, and zero-knowledge.

#### Acceptance Criteria

1. THE System SHALL implement cq+ reducing proof size from 8 G_1 to 7 G_1 elements
2. THE System SHALL implement cq++ reducing proof size from 7 G_1 to 6 G_1 elements with one additional pairing
3. THE System SHALL implement zkcq+ providing full zero-knowledge (hiding both table and witness) with 9 G_1 proof size
4. THE System SHALL implement cq+(zk) hiding witness only with 8 G_1 proof size
5. THE System SHALL implement cq++(zk) hiding witness only with 7 G_1 proof size
6. THE System SHALL maintain prover cost 8n G_1 + O(n log n) F for all variants
7. THE System SHALL maintain preprocessing cost O(N log N) for all variants
8. THE System SHALL support vector lookups via homomorphic table linearization

### Requirement 18: Subvector Extraction (Caulk/Caulk+)

**User Story:** As a position-hiding lookup developer, I want to implement Caulk/Caulk+, so that I can achieve sublinear lookups with position-hiding linkability.

#### Acceptance Criteria

1. THE System SHALL extract subtable t_I containing all table elements appearing in witness
2. THE System SHALL compute commitment to t_I(X) efficiently via subvector aggregation techniques
3. THE System SHALL prove identity: t(X) - t_I(X) = z_I(X) · q_I(X)
4. THE System SHALL compute commitment to quotient q_I(X) via linear combination of preprocessed commitments
5. THE System SHALL prove z_I(X) vanishes over correct roots without revealing indices I
6. THE System SHALL verify z_I(X) · Q(X) = z_Ω(X) = X^N - 1 for quotient Q(X)
7. THE System SHALL map indices I into subgroup of order |I| for efficient vanishing polynomial computation
8. THE System SHALL achieve Caulk prover cost O(n^2 + n log N)
9. THE System SHALL achieve Caulk+ prover cost O(n^2)
10. THE System SHALL achieve verifier cost O(1) with constant proof size
11. THE System SHALL require preprocessing cost O(N log N)

### Requirement 19: Subvector Extraction (Baloo)

**User Story:** As a Baloo implementer, I want to build on matrix-vector technique, so that I can achieve nearly optimal lookup arguments.

#### Acceptance Criteria

1. THE System SHALL represent lookup as matrix-vector product: M × t_I = w where M is elementary matrix
2. THE System SHALL extract subtable t_I efficiently using preprocessed polynomials
3. THE System SHALL reduce matrix-vector equation to scalar relation: (r × M) · t_I = r · w for random r
4. THE System SHALL ensure prover work remains independent of original table size
5. THE System SHALL achieve prover cost O(n log^2 n)
6. THE System SHALL achieve verifier cost O(1) with constant proof size
7. THE System SHALL require preprocessing cost O(N log N)
8. THE System SHALL support zero-knowledge variant

### Requirement 20: Lasso Technique

**User Story:** As a Jolt zkVM developer, I want to implement Lasso, so that I can support structured and decomposable tables with efficient lookups in massive tables.

#### Acceptance Criteria

1. THE System SHALL model lookup as matrix-vector multiplication: M_{n×N} × t_{N×1} = w_{n×1} where M is elementary matrix
2. THE System SHALL verify multilinear extension identity: Σ_{y∈{0,1}^{log N}} M̃(r, y) · t̃(y) = w̃(r) for random r
3. THE System SHALL apply sumcheck protocol to reduce to evaluations of M̃(r_1, r_2), t̃(r_1), w̃(r_2)
4. THE System SHALL commit to sparse M̃ using Spark polynomial commitment scheme
5. THE System SHALL represent M as {(row_i, col_i, val_i)} specifying non-zero entry positions
6. THE System SHALL commit only to row and column indices (values are all 1)
7. THE System SHALL verify M is elementary by checking row indices equal [0, n)
8. THE System SHALL support structured tables with efficiently computable multilinear extensions
9. THE System SHALL support decomposable tables reducing large table lookups to smaller table lookups
10. THE System SHALL achieve prover cost O(N + n) for structured tables
11. THE System SHALL achieve prover cost O(cn) for decomposable tables where c is decomposition factor
12. THE System SHALL achieve verifier cost O(log^2 n)
13. THE System SHALL require NO preprocessing for structured tables
14. THE System SHALL support non-homomorphic PCS including hash-based schemes


### Requirement 21: Spark Sparse Polynomial Commitment

**User Story:** As a Lasso implementer, I want to implement Spark, so that I can efficiently commit to and open sparse multilinear polynomials.

#### Acceptance Criteria

1. THE System SHALL represent sparse polynomial f with N variables by non-zero entries {(w, f(w))}
2. THE System SHALL compute evaluation f(x) = Σ_{w: f(w)≠0} f(w) · eq(x, w)
3. THE System SHALL exploit tensor-product structure: eq(x_1 ∥ x_2, w_1 ∥ w_2) = eq(x_1, w_1) · eq(x_2, w_2)
4. THE System SHALL split evaluation point x into c segments x_1, ..., x_c each of length log(N/c)
5. THE System SHALL construct c tables T_i = {eq(x_i, w) : w ∈ {0,1}^{log(N/c)}}
6. THE System SHALL choose c such that N = c · n for constant-sized tables of size n
7. THE System SHALL perform c · n lookups total across c tables
8. THE System SHALL achieve commitment time O(n) independent of N
9. THE System SHALL achieve opening time O(n) independent of N
10. THE System SHALL support maliciously committed polynomials with evaluation binding
11. THE System SHALL NOT provide zero-knowledge in base form

### Requirement 22: Generalized Lasso

**User Story:** As a developer working with unstructured tables, I want to implement Generalized Lasso, so that I can handle tables whose multilinear extensions are efficiently computable but not decomposable.

#### Acceptance Criteria

1. THE System SHALL apply sparse sumcheck protocol to avoid computation over zero entries in M̃
2. THE System SHALL reduce to random evaluations of M̃, t̃, w̃ after sumcheck
3. THE System SHALL commit to M̃ using Spark
4. THE System SHALL commit to w̃ using dense polynomial commitment
5. THE System SHALL enable verifier to evaluate t̃ directly (efficiently computable MLE)
6. THE System SHALL achieve prover cost dependent on sparsity of M̃
7. THE System SHALL support tables with sublinear-time evaluable multilinear extensions

### Requirement 23: Projective Lasso

**User Story:** As a Lasso user, I want to support projective lookups, so that I can selectively verify witness indices without committing to full witness.

#### Acceptance Criteria

1. THE System SHALL allow matrix M to contain elementary rows (one entry = 1) and all-zero rows
2. THE System SHALL commit to vector {row_i} of non-zero positions during setup
3. THE System SHALL verify row indices correspond to witness entries intended for lookup
4. THE System SHALL maintain all other protocol steps unchanged from standard Lasso
5. THE System SHALL incur minimal overhead for committing to row index vector
6. THE System SHALL enable selective witness verification without explicit bookkeeping in circuit

### Requirement 24: Shout Technique

**User Story:** As a performance optimizer, I want to implement Shout, so that I can improve upon Lasso by reducing commitment costs for sparse matrices.

#### Acceptance Criteria

1. THE System SHALL implement Shout-1 committing to map matrix M without Spark
2. THE System SHALL exploit that committing to 0s and 1s is 2-3 orders of magnitude cheaper than random elements
3. THE System SHALL commit to n ones where n is number of lookups
4. THE System SHALL implement Shout-d for d > 1 decomposing basis vectors into tensor products
5. THE System SHALL decompose each one-hot vector of length K into d vectors of length K^{1/d}
6. THE System SHALL commit to (d-1) · N^{1/d} zeros and d ones per entry in original matrix
7. THE System SHALL trade commitment cost for higher-complexity rank-d constraints
8. THE System SHALL support curve-based PCS (Hyrax, KZH) for small tables
9. THE System SHALL support hash-based PCS with reduced commitment overhead
10. THE System SHALL achieve prover cost O(cn) for decomposable tables with parameter d
11. THE System SHALL achieve verifier cost O(d log n)


### Requirement 25: Accumulator-Based Lookups (Flookup)

**User Story:** As a pairing-based accumulator user, I want to implement Flookup, so that I can achieve efficient lookups using batch commit-and-prove openings.

#### Acceptance Criteria

1. THE System SHALL commit to table t and subtable t' using pairing-based accumulators
2. THE System SHALL generate single proof that t' ⊆ t with batch opening
3. THE System SHALL precompute opening proofs for each table element during preprocessing
4. THE System SHALL generate proof with time dependent only on subtable size |t'|
5. THE System SHALL prove each witness entry w_i ∈ t' where w is committed vector
6. THE System SHALL achieve prover cost O(n log^2 n)
7. THE System SHALL achieve verifier cost O(1) with constant proof size
8. THE System SHALL require preprocessing cost O(N log N)

### Requirement 26: Accumulator-Based Lookups (Duplex)

**User Story:** As a transparent setup advocate, I want to implement Duplex, so that I can achieve zero-knowledge lookups over RSA groups with constant-size public parameters.

#### Acceptance Criteria

1. THE System SHALL commit to table using RSA group or class group accumulators
2. THE System SHALL support groups of unknown order including transparent instantiations
3. THE System SHALL provide constant-size public parameters
4. THE System SHALL link RSA accumulators with Pedersen commitments in prime order group
5. THE System SHALL avoid encoding RSA operations inside arithmetic circuit
6. THE System SHALL support witness vectors with duplicate elements
7. THE System SHALL provide zero-knowledge hiding both table and witness
8. THE System SHALL achieve prover cost O(n log n)
9. THE System SHALL achieve verifier cost O(1) with constant proof size
10. THE System SHALL require preprocessing cost O(N log N)

### Requirement 27: Preprocessing PIOP Framework

**User Story:** As a PIOP designer, I want to implement preprocessing PIOP framework, so that I can separate offline preprocessing from online proving.

#### Acceptance Criteria

1. THE System SHALL implement offline phase I(I) generating preprocessing oracle polynomials p_1, ..., p_i
2. THE System SHALL provide verifier with oracle access ix to preprocessing polynomials
3. THE System SHALL provide prover with actual polynomials iw
4. THE System SHALL implement online phase ⟨P(iw, w), V(ix, x)⟩ as interactive protocol
5. THE System SHALL allow prover to send oracle polynomials in each round
6. THE System SHALL allow verifier to send random challenges in each round
7. THE System SHALL enable verifier to query all oracles at arbitrary points
8. THE System SHALL ensure completeness: honest execution always accepts
9. THE System SHALL ensure δ-knowledge soundness with extractor E
10. THE System SHALL support zero-knowledge via simulator generating indistinguishable transcripts
11. THE System SHALL assume preprocessing polynomials are committed honestly
12. THE System SHALL require evaluation binding for prover-generated polynomials
13. THE System SHALL require only weak binding for preprocessed polynomials

### Requirement 28: Sumcheck Protocol

**User Story:** As a proof system implementer, I want to implement sumcheck protocol, so that I can efficiently verify polynomial summations.

#### Acceptance Criteria

1. GIVEN ℓ-variate polynomial g over field F, THE System SHALL enable prover to provide sum H := Σ_{b∈{0,1}^ℓ} g(b)
2. THE System SHALL reduce summation claim to evaluation claim g(r) at random point r ∈ F^ℓ
3. THE System SHALL achieve verifier runtime O(ℓ) plus time to evaluate g at single point
4. THE System SHALL implement univariate sumcheck lemma: Σ_{a∈H} f(a) = t · f(0) for subgroup H of size t
5. THE System SHALL support multilinear sumcheck for multilinear polynomials
6. THE System SHALL enable batching of multiple sumcheck instances
7. THE System SHALL provide exponential speedup over naive 2^ℓ verification


### Requirement 29: Accumulation Scheme Framework

**User Story:** As a recursive proof developer, I want to implement accumulation scheme framework, so that I can build efficient IVC and PCD systems.

#### Acceptance Criteria

1. THE System SHALL implement Setup_acc(1^λ) generating public parameters srs_acc
2. THE System SHALL implement P_acc(st, π, acc_1) outputting new accumulator acc and proof pf
3. THE System SHALL implement V_acc(acc_1.x, acc_2.x, pf) outputting new accumulator instance acc.x
4. THE System SHALL implement D_acc(acc) accepting or rejecting accumulator
5. THE System SHALL ensure completeness: for ϕ(π) = 1 and D_acc(acc) = 1, verification succeeds
6. THE System SHALL ensure knowledge-soundness: extractor E exists for adversary A
7. THE System SHALL reduce satisfiability of two NP statements into single accumulated statement
8. THE System SHALL achieve non-trivial accumulation: verification cost less than two separate verifications
9. THE System SHALL support BCLMS compiler to construct IVC/PCD from accumulation scheme

### Requirement 30: Protostar Lookup Accumulation

**User Story:** As an IVC developer, I want to implement Protostar lookup accumulation, so that I can efficiently accumulate lookup checks in recursive proofs.

#### Acceptance Criteria

1. THE System SHALL transform lookup relation into special-sound protocol using Logup lemma
2. THE System SHALL apply Protostar compiler to construct accumulation scheme for lookup
3. THE System SHALL compose R1CS special-sound protocol with lookup special-sound protocol
4. THE System SHALL support projective lookups via projective Logup lemma (Lemma 4)
5. THE System SHALL achieve accumulator prover cost O(n) group operations per IVC step
6. THE System SHALL achieve accumulator verifier cost O(1) field operations, O(1) hash operations, 3 group operations
7. THE System SHALL achieve accumulator decider cost O(N) group operations
8. THE System SHALL require homomorphic vector commitment (HVC) assumption
9. THE System SHALL support IVC efficiently but NOT PCD efficiently
10. THE System SHALL maintain prover cost independent of table size for IVC
11. THE System SHALL require Pedersen commitment setup proportional to table size
12. THE System SHALL support decomposable tables via FLI extension

### Requirement 31: nLookup (HyperNova) Accumulation

**User Story:** As a HyperNova user, I want to implement nLookup, so that I can accumulate indexed lookups efficiently without large prime field requirement.

#### Acceptance Criteria

1. GIVEN table t of size N = 2^k as function t: {0,1}^k → F, THE System SHALL extend to multilinear extension t̃(x_1, ..., x_k)
2. GIVEN m indexed lookups {(q_i, v_i)}_{i∈[m]} where q_i ∈ {0,1}^k, THE System SHALL verify v_i = t̃(q_i)
3. THE System SHALL use sumcheck-based folding to reduce m evaluations to single evaluation at random point
4. THE System SHALL reveal all lookup entries in plaintext (not committed)
5. THE System SHALL support projective lookups by selective witness checking
6. THE System SHALL achieve verifier cost O(log N) field and hash operations + O(m log N) field operations
7. THE System SHALL perform implicit smallness test via Boolean vector representation of indices
8. THE System SHALL achieve prover cost O(N) field operations per step
9. THE System SHALL achieve decider cost O(2^k) field operations (or less for structured tables)
10. THE System SHALL NOT require large prime field (compatible with small fields)
11. THE System SHALL NOT require homomorphic commitments (compatible with hash-based PCS)

### Requirement 32: FLI (Folding Lookup Instances)

**User Story:** As a Jolt continuation developer, I want to implement FLI, so that I can make Lasso lookups compatible with recursive proof systems.

#### Acceptance Criteria

1. THE System SHALL represent lookup as matrix-vector product: M · t = w where M is elementary matrix
2. THE System SHALL commit to table Com(t), witness Com(w), and matrix Com(M)
3. THE System SHALL accumulate linear constraint M · t = w via linear combinations: (M_1 + α · M_2) · t = w_1 + α · w_2
4. THE System SHALL enforce M is elementary via identities: M · M = M and M · I = I where I = (1 1 ... 1)
5. THE System SHALL use Nova-inspired techniques to handle R1CS-style constraints
6. THE System SHALL require homomorphic commitment scheme for matrices
7. THE System SHALL support decomposable tables by decomposing into smaller base tables
8. THE System SHALL achieve accumulator prover cost O(n) group operations + O(n) field operations
9. THE System SHALL achieve accumulator verifier cost O(1) field operations, O(1) hash operations, 4 group operations
10. THE System SHALL achieve accumulator decider cost O(N · n) group operations
11. THE System SHALL accept sparsity loss in accumulated matrix M over multiple rounds
12. THE System SHALL maintain practical efficiency for Jolt-style decomposed tables of size 2^16


### Requirement 33: KZG Polynomial Commitment

**User Story:** As a pairing-based proof system developer, I want to implement KZG commitment scheme, so that I can leverage homomorphic properties and efficient batch openings.

#### Acceptance Criteria

1. THE System SHALL implement KZG Setup generating structured reference string from trusted setup
2. THE System SHALL implement KZG Commit computing commitment C = [p(s)]_1 for polynomial p
3. THE System SHALL implement KZG Open computing proof π for evaluation p(x) = y
4. THE System SHALL implement KZG Verify checking pairing equation e(C - [y]_1, [1]_2) = e(π, [s - x]_2)
5. THE System SHALL support batch opening at multiple points with O(d log^2 d) amortized time
6. THE System SHALL support batch opening at subgroup with O(d log d) time
7. THE System SHALL provide homomorphic commitment: Com(p_1 + p_2) = Com(p_1) + Com(p_2)
8. THE System SHALL provide homomorphic opening: Open(p_1 + p_2, x) computable from Open(p_1, x) and Open(p_2, x)
9. THE System SHALL achieve constant-size commitments and proofs
10. THE System SHALL require trusted setup ceremony
11. THE System SHALL support univariate polynomials over large prime fields

### Requirement 34: Multilinear Extension

**User Story:** As a multilinear polynomial user, I want to implement multilinear extensions, so that I can work with functions over Boolean hypercubes.

#### Acceptance Criteria

1. GIVEN function f: {0,1}^n → F, THE System SHALL compute unique multilinear extension f̃: F^n → F
2. THE System SHALL ensure f̃ has degree at most 1 in each variable
3. THE System SHALL ensure f̃(b) = f(b) for all b ∈ {0,1}^n
4. THE System SHALL implement eq̃ function: eq̃(x, e) = ∏_{i=1}^s (x_i · e_i + (1 - x_i) · (1 - e_i))
5. THE System SHALL verify eq̃(x, e) = 1 if and only if x = e
6. THE System SHALL extend vectors u ∈ F^m to multilinear polynomial ũ
7. THE System SHALL extend matrices M_{n×m} to multilinear polynomial M̃: {0,1}^{log n} × {0,1}^{log m} → F
8. THE System SHALL support efficient evaluation of structured multilinear extensions

### Requirement 35: GKR Protocol

**User Story:** As a layered circuit prover, I want to implement GKR protocol, so that I can prove circuit computations with commitments only to input/output layers.

#### Acceptance Criteria

1. THE System SHALL support layered arithmetic circuits with simple polynomial descriptions
2. THE System SHALL require commitments only to input and output layers
3. THE System SHALL avoid committing to intermediate wires
4. THE System SHALL achieve prover cost dominated by field operations (cheaper than group operations)
5. THE System SHALL require circuit to have simple layered structure
6. THE System SHALL support uniform circuits where each layer admits simple polynomial description
7. THE System SHALL enable preprocessing of layer descriptions
8. THE System SHALL provide verifier cost O(log(circuit_size))

### Requirement 36: Compatibility and Composition

**User Story:** As a proof system integrator, I want to ensure compatibility between lookup schemes and underlying proof systems, so that I can compose them efficiently.

#### Acceptance Criteria

1. THE System SHALL verify lookup scheme and proof system operate over same finite structure (same field)
2. THE System SHALL ensure structural compatibility: shared commitment or same PCS
3. THE System SHALL support argument-level composition via commit-and-prove paradigm
4. THE System SHALL support PIOP-level composition via sequential PIOP composition
5. THE System SHALL enable compilation of composed PIOP into argument via PCS
6. THE System SHALL provide better modularity with commit-and-prove (plug-and-play architecture)
7. THE System SHALL provide better efficiency with PIOP-level composition (batched openings, smaller proofs)
8. THE System SHALL support dual polynomial commitments for univariate-multivariate bridging
9. THE System SHALL verify compatibility between KZG (univariate) and multilinear schemes
10. THE System SHALL support hash-based PCS compatibility with Logup and Lasso techniques


### Requirement 37: Table Size and Performance Considerations

**User Story:** As a performance analyst, I want to understand table size impact on performance, so that I can choose appropriate lookup schemes for different table sizes.

#### Acceptance Criteria

1. THE System SHALL classify schemes as table-efficient if prover runtime is sublinear in table size
2. THE System SHALL classify schemes as super-sublinear if prover runtime is independent of table size
3. THE System SHALL support structured tables with sublinear-time evaluable multilinear extensions
4. THE System SHALL support decomposable tables reducing large lookups to smaller table lookups
5. THE System SHALL identify preprocessing-based schemes requiring O(N log N) preprocessing
6. THE System SHALL recognize cq family achieves best proving time but expensive preprocessing (≈2^37 ops for 2^32 table)
7. THE System SHALL recognize Lasso family achieves best tradeoffs for structured tables
8. THE System SHALL recognize non-black-box solutions (Merkle tree + SNARK) offer balanced preprocessing/proving
9. THE System SHALL identify research gaps: efficient non-pairing schemes, lightweight preprocessing, other table structures
10. THE System SHALL support small tables (|t| ≤ |w|) efficiently with multiset equality techniques

### Requirement 38: Application Support - Non-Native Operations

**User Story:** As a zkVM developer, I want to use lookups for non-native operations, so that I can reduce constraint counts for bit decomposition, range checks, comparisons, and hash functions.

#### Acceptance Criteria

1. THE System SHALL support bit decomposition via lookup tables
2. THE System SHALL support range proofs via lookup tables
3. THE System SHALL support value comparison via lookup tables
4. THE System SHALL support floating-point arithmetic via lookup tables
5. THE System SHALL support hash function operations (e.g., Poseidon, Reinforced Concrete) via lookup tables
6. THE System SHALL prefer Lasso family for small or structured tables
7. THE System SHALL support decomposable tables for operations on large bit-widths (e.g., 32-bit vs 8-bit chunks)
8. THE System SHALL enable batching of multiple lookup operations
9. THE System SHALL reduce circuit size compared to native arithmetic encoding

### Requirement 39: Application Support - Set Membership

**User Story:** As a blockchain developer, I want to use lookups for set membership, so that I can prove elements belong to large unstructured sets like public key registries.

#### Acceptance Criteria

1. THE System SHALL support proving all elements in commitment belong to given set
2. THE System SHALL support large unstructured sets (e.g., public key databases)
3. THE System SHALL prefer table-efficient schemes for large unstructured sets
4. THE System SHALL support preprocessing-based schemes (cq, Caulk+, Baloo) for moderate-size sets
5. THE System SHALL support non-black-box solutions (Merkle tree accumulators) for very large sets
6. THE System SHALL enable efficient membership proofs without revealing set elements
7. THE System SHALL support position-hiding linkability where applicable

### Requirement 40: Application Support - Memory Correctness

**User Story:** As a zkVM architect, I want to use lookups for memory correctness, so that I can prove read/write transcript consistency in verifiable computation.

#### Acceptance Criteria

1. THE System SHALL support read-only memory abstraction via lookup tables
2. THE System SHALL support indexed lookups for memory address-value pairs
3. THE System SHALL support online lookup tables for runtime-dependent memory
4. THE System SHALL support write operations via updatable lookup tables (Proofs for Deep Thoughts)
5. THE System SHALL support state machine transition rules via lookup tables
6. THE System SHALL support finite automata via lookup tables
7. THE System SHALL prefer indexed lookup arguments with preprocessing for large unstructured memory
8. THE System SHALL identify open problem: efficient updatable tables with state-of-the-art preprocessing performance


### Requirement 41: Application Support - Extractor Strengthening

**User Story:** As a proof system theorist, I want to use lookups for extractor strengthening, so that I can ensure extracted witnesses belong to finite domains.

#### Acceptance Criteria

1. THE System SHALL support proving witness belongs to finite set to strengthen extractor
2. THE System SHALL enable extraction of integer witnesses from rational number extractors
3. THE System SHALL compose lookup PIOP with main PIOP to ensure witness domain membership
4. THE System SHALL recognize complexity tradeoff: verifier time Ω(max(2^{B/2}, √n)) for B-bit integers
5. THE System SHALL support alternative constructions (e.g., Spartan-like for integer relations) with better asymptotics
6. THE System SHALL enable knowledge soundness for bounded integer witnesses

### Requirement 42: Projective Ratio Considerations

**User Story:** As a circuit optimizer, I want to understand projective ratio impact, so that I can determine when lookup arguments provide efficiency gains.

#### Acceptance Criteria

1. THE System SHALL analyze proportion of witness subject to lookup checks
2. THE System SHALL recognize overhead may exceed benefit for very small projective ratios
3. THE System SHALL support efficient projective lookups via selector vectors
4. THE System SHALL avoid linear-cost witness selection when projective ratio is small
5. THE System SHALL recommend lookup arguments when projective ratio is substantial relative to total witness size
6. THE System SHALL provide guidance on break-even points for different lookup techniques

### Requirement 43: Zero-Knowledge Properties

**User Story:** As a privacy-focused developer, I want to implement zero-knowledge lookup arguments, so that I can hide witness values while proving lookup relations.

#### Acceptance Criteria

1. THE System SHALL support zero-knowledge via simulator generating indistinguishable transcripts
2. THE System SHALL hide witness in standard zero-knowledge lookups
3. THE System SHALL hide both witness and table in full zero-knowledge lookups (zkcq+, Duplex)
4. THE System SHALL support zero-knowledge compilation of PIOPs via hiding PCS and zero-knowledge opening
5. THE System SHALL provide zero-knowledge variants: Caulk, Caulk+, cq+(zk), cq++(zk), zkcq+
6. THE System SHALL recognize most lookup PIOPs presented without zero-knowledge (extension left for future work)
7. THE System SHALL support position-hiding linkability in Caulk/Caulk+
8. THE System SHALL ensure table remains public in standard zero-knowledge (part of index, not witness)

### Requirement 44: Recursive Proof Integration

**User Story:** As an IVC/PCD developer, I want to integrate lookups with recursive proofs, so that I can build efficient zkVMs with continuation support.

#### Acceptance Criteria

1. THE System SHALL support lookup accumulation schemes for IVC construction
2. THE System SHALL implement Protostar accumulation for special-sound lookup protocols
3. THE System SHALL implement nLookup accumulation for HyperNova-style folding
4. THE System SHALL implement FLI accumulation for Lasso-style lookups
5. THE System SHALL achieve non-trivial accumulation: verification cost less than separate verifications
6. THE System SHALL support BCLMS compiler from accumulation to IVC/PCD
7. THE System SHALL recognize Protostar/FLI efficient for IVC but not PCD
8. THE System SHALL support decomposable table accumulation via FLI extension
9. THE System SHALL manage sparsity loss in accumulated matrices over multiple rounds
10. THE System SHALL enable zkVM continuation by dividing programs into chunks with aggregated proofs

### Requirement 45: Field Characteristic Requirements

**User Story:** As a field selection analyst, I want to understand field characteristic requirements, so that I can choose appropriate fields for different lookup techniques.

#### Acceptance Criteria

1. THE System SHALL support Logup-based techniques requiring characteristic p > max(n, N)
2. THE System SHALL support small prime fields (e.g., BabyBear p = 2^31 - 1) for Logup
3. THE System SHALL NOT support binary fields (characteristic 2) for Logup
4. THE System SHALL support multiset equality techniques (Plookup, Halo2) without large field requirement
5. THE System SHALL support Lasso/Shout techniques adaptable to binary fields and rings
6. THE System SHALL support KZG-based techniques requiring large prime fields (≈256 bits)
7. THE System SHALL provide guidance on field selection based on technique and application requirements


### Requirement 46: Comparison with Related Primitives

**User Story:** As a cryptographic primitive analyst, I want to understand relationships with related primitives, so that I can choose appropriate tools for different scenarios.

#### Acceptance Criteria

1. THE System SHALL distinguish lookup arguments from set accumulators: lookups support duplicates in witness
2. THE System SHALL distinguish lookup arguments from vector commitments: lookups provide commit-and-prove on both sides
3. THE System SHALL recognize lookup arguments generalize set membership proofs with commit-and-prove functionality
4. THE System SHALL distinguish lookup tables from memory checking: lookups are read-only, memory checking supports writes
5. THE System SHALL distinguish standard lookups from updateable lookups: standard tables fixed after preprocessing
6. THE System SHALL distinguish updateable lookups from online lookups: updateable can be modified multiple times online
7. THE System SHALL recognize table typically public in lookups vs potentially private in accumulators/vector commitments
8. THE System SHALL support offline memory checking techniques (Spark) for online lookup table construction

### Requirement 47: Preprocessing Efficiency and Scalability

**User Story:** As a system deployer, I want to understand preprocessing costs, so that I can determine feasibility for different table sizes.

#### Acceptance Criteria

1. THE System SHALL quantify preprocessing cost O(N log N) for KZG-based schemes
2. THE System SHALL recognize cq preprocessing requires ≈2^37 group operations for 2^32 table (days on high-performance server)
3. THE System SHALL identify preprocessing as bottleneck for very large tables (>2^32)
4. THE System SHALL support schemes without preprocessing: Plookup, Halo2, Logup+GKR, Lasso (structured)
5. THE System SHALL support lightweight preprocessing via Merkle trees for non-black-box solutions
6. THE System SHALL recognize preprocessing amortizes over multiple proofs for same table
7. THE System SHALL identify open problem: black-box solutions with balanced preprocessing/proving for large tables

### Requirement 48: Proof Size and Verification Cost

**User Story:** As a blockchain developer, I want to minimize proof size and verification cost, so that I can deploy efficient on-chain verifiers.

#### Acceptance Criteria

1. THE System SHALL achieve constant proof size for KZG-based schemes (6-9 G_1 elements)
2. THE System SHALL achieve O(log^2 n) proof size for Lasso-based schemes
3. THE System SHALL achieve O(log(N+n)) proof size for Logup+GKR
4. THE System SHALL achieve constant verification cost O(1) for most schemes
5. THE System SHALL achieve O(log^2 n) verification cost for Lasso
6. THE System SHALL achieve O(log(N+n)) verification cost for Logup+GKR
7. THE System SHALL support pairing-based verification (5-6 pairings) for KZG schemes
8. THE System SHALL support hash-based verification for FRI-based schemes
9. THE System SHALL enable batching of verification across multiple proofs

### Requirement 49: Concrete Performance Benchmarks

**User Story:** As a performance engineer, I want concrete performance data, so that I can make informed implementation decisions.

#### Acceptance Criteria

1. THE System SHALL benchmark prover time for different table sizes: 2^16, 2^20, 2^24, 2^28, 2^32
2. THE System SHALL benchmark preprocessing time for different schemes and table sizes
3. THE System SHALL benchmark proof generation time for different witness sizes: 2^10, 2^15, 2^20
4. THE System SHALL benchmark verification time for different schemes
5. THE System SHALL measure concrete costs: group operations, field operations, hash operations, pairings
6. THE System SHALL compare committing to small elements (0/1) vs random elements (≈10× difference)
7. THE System SHALL benchmark decomposable table performance with different decomposition factors
8. THE System SHALL measure memory consumption for different schemes
9. THE System SHALL provide performance profiles for different hardware configurations

### Requirement 50: Security Assumptions and Trust Models

**User Story:** As a security analyst, I want to understand security assumptions, so that I can assess trust requirements for different schemes.

#### Acceptance Criteria

1. THE System SHALL identify KZG-based schemes requiring trusted setup ceremony
2. THE System SHALL identify transparent schemes: Plookup, Halo2, Logup+GKR, Lasso, Shout
3. THE System SHALL specify pairing assumptions for KZG-based schemes (q-SDH, q-DLOG)
4. THE System SHALL specify RSA assumptions for Duplex (strong RSA, adaptive root)
5. THE System SHALL specify discrete log assumptions for Pedersen-based schemes
6. THE System SHALL specify collision-resistance assumptions for hash-based schemes
7. THE System SHALL identify homomorphic vector commitment (HVC) assumption for Protostar/FLI
8. THE System SHALL distinguish computational soundness from information-theoretic soundness
9. THE System SHALL specify knowledge soundness with extractor guarantees
10. THE System SHALL identify post-quantum security considerations (hash-based schemes resistant, pairing-based not)
