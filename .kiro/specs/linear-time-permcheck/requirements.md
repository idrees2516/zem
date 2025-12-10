# Requirements Document: Linear-Time Permutation Check

## Introduction

This document specifies the requirements for implementing the Linear-Time Permutation Check protocol as described in "Linear*-Time Permutation Check" by Benedikt Bünz, Jessica Chen, and Zachary DeStefano (NYU, 2025). The protocol provides permutation and lookup arguments with polylogarithmic soundness error, logarithmic verification cost, and linear or near-linear prover time without requiring commitment to additional witness data beyond the original witness.

## Glossary

- **SNARK**: Succinct Non-interactive ARgument of Knowledge - a cryptographic proof system
- **PIOP**: Polynomial Interactive Oracle Proof - an information-theoretic protocol underlying SNARKs
- **PCS**: Polynomial Commitment Scheme - cryptographic primitive for committing to polynomials
- **Permutation Check**: Protocol proving that f(x) = g(σ(x)) for all x in domain H, where σ is a permutation
- **Lookup Argument**: Protocol proving that witness values exist in a preprocessed table
- **Sumcheck Protocol**: Interactive proof protocol for verifying polynomial evaluations over boolean hypercube
- **MLE**: Multilinear Extension - unique multilinear polynomial extending a function from boolean hypercube
- **Boolean Hypercube**: Set B^μ = {0,1}^μ representing all μ-bit binary strings
- **Soundness Error**: Probability that malicious prover convinces verifier of false statement
- **Field**: Finite field F with |F| elements, typically large prime field
- **BiPerm**: Linear-time permutation check requiring sparse PCS (2-way split)
- **MulPerm**: Almost-linear permutation check working with any PCS (multi-way split)
- **GKR Protocol**: Goldwasser-Kalai-Rothblum protocol for delegating computation verification
- **Fiat-Shamir Transform**: Technique converting interactive protocols to non-interactive using hash functions
- **Sparse PCS**: Polynomial commitment scheme where cost depends only on non-zero entries
- **HyperPlonk**: SNARK system using multilinear polynomials and permutation checks
- **Spartan**: SNARK system for R1CS using GKR and memory checking
- **SPARK Compiler**: Component in Spartan for committing to sparse polynomials
- **R1CS**: Rank-1 Constraint System - arithmetic circuit representation
- **Indicator Function**: Function 1_σ(X,Y) that equals 1 when σ(X)=Y, 0 otherwise
- **Arithmetization**: Process of representing boolean functions as polynomials
- **Bucketing Algorithm**: Optimization technique grouping similar polynomial evaluations


## Requirements

### Requirement 1: Core Mathematical Primitives

**User Story:** As a cryptographic protocol implementer, I want to implement the fundamental mathematical primitives used throughout the permutation check protocols, so that I can build the higher-level protocols on a solid foundation.

#### Acceptance Criteria

1. WHEN computing the equality polynomial eq(X,Y) for X,Y ∈ F^μ THEN the system SHALL compute eq(X,Y) := ∏_{i=1}^μ [X_i Y_i + (1-X_i)(1-Y_i)]

2. WHEN evaluating eq(x,y) for x,y ∈ B^μ THEN the system SHALL return 1 if x_i = y_i for all i ∈ [μ], and 0 otherwise

3. WHEN computing multilinear extension f̃ of function f: B^μ → F THEN the system SHALL compute f̃(X) = ∑_{b∈B^μ} f(b) · eq(b,X)

4. WHEN evaluating eq(y_L, α_L) at all points y_L ∈ B^{μ/2} THEN the system SHALL complete computation in O(2^{μ/2}) = O(√n) time

5. WHEN representing permutation σ: B^μ → B^μ as multilinear map THEN the system SHALL compute σ̃(X) = (σ̃_1(X),...,σ̃_μ(X)) where each σ̃_i is the MLE of the i-th bit of σ

6. WHEN interpolating permutation bits into single polynomial THEN the system SHALL compute σ̃_{[μ]}(I,X): F^{μ+log μ} → F where σ̃_{[μ]}(⟨i⟩,X) := σ̃_i(X) for all i ∈ [μ]

7. WHEN computing indicator function 1_σ(X,Y) THEN the system SHALL ensure 1_σ(X,Y) = 1 if σ(X)=Y and 0 otherwise for all X,Y ∈ B^μ

8. WHEN arithmetizing indicator function THEN the system SHALL compute 1̃_σ(X,Y) = eq(σ̃(X),Y) = ∏_{i=1}^μ eq(σ̃_i(X),Y_i)


### ### 2: Sumcheck Protocol Implementation

**User Story:** As a protocol developer, I want to implement the sumcheck protocol with all optimizations, so that I can efficiently verify polynomial evaluations over the boolean hypercube.

#### Acceptance Criteria

1. WHEN running sumcheck for ∑_{x∈B^μ} f(x) = v THEN the system SHALL execute μ rounds where round k computes u_k(X) := ∑_{x∈B^{μ-k}} f(α_{1:k-1}, X, x)

2. WHEN prover sends round polynomial u_k THEN the system SHALL send it as oracle [[u_k]] rather than explicit coefficients to reduce communication

3. WHEN verifier receives u_k(X) of degree d THEN the system SHALL check u_k(0) + u_k(1) = S where S is the claimed sum from previous round

4. WHEN verifier samples challenge α_k ∈ F THEN the system SHALL update S ← u_k(α_k) for next round

5. WHEN sumcheck completes after μ rounds THEN the system SHALL verify f(α) = S by querying oracle [[f]] at point α ∈ F^μ

6. WHEN sumcheck has degree d in each variable THEN the system SHALL achieve soundness error δ_SUM^{d,μ} := dμ/|F|

7. WHEN prover sends degree d-2 polynomial u'_k and value u_k(0) THEN the system SHALL reconstruct three evaluations u_k(0), u_k(1), u_k(α_k) with single oracle query

8. WHEN computing round polynomial u_k(X) THEN the system SHALL use FFT to multiply μ+1 lists of μ+2 evaluation points in time Õ(2^{μ-k})

9. WHEN batching multiple sumcheck instances THEN the system SHALL use random linear combination to reduce to single sumcheck verification


### ### 3: Permutation Check Reduction to Sumcheck

**User Story:** As a SNARK developer, I want to reduce permutation checking to sumcheck formulation, so that I can prove f(x) = g(σ(x)) for all x efficiently.

#### Acceptance Criteria

1. WHEN proving permutation relation (σ̃, [[σ̃]]; [[f]], [[g]]; f, g) ∈ R_PERM THEN the system SHALL verify f(x) = g(σ(x)) for all x ∈ B^μ

2. WHEN reducing to sumcheck THEN the system SHALL prove ∑_{x∈B^μ} f(x) · 1̃_σ(x,α) = g(α) for random challenge α ∈ F^μ

3. WHEN verifier samples α ∈ F^μ THEN the system SHALL query [[g]] to obtain S ← g(α) as the claimed sum

4. WHEN sumcheck reduces to final claim THEN the system SHALL verify f(β) · 1̃_σ(β,α) = S for random β ∈ F^μ

5. WHEN using Schwartz-Zippel lemma THEN the system SHALL achieve soundness error μ/|F| for the reduction step

6. WHEN combining with sumcheck soundness THEN the system SHALL achieve total soundness error O(μ²/|F|) = O(log²n/|F|)

7. WHEN f and g are multilinear polynomials THEN the system SHALL ensure the sumcheck formulation preserves multilinearity in verification

8. WHEN permutation σ is preprocessed THEN the system SHALL include [[σ̃]] in the index i accessible to verifier


### ### 4: BiPerm Protocol - Linear Time Permutation Check

**User Story:** As a performance-focused developer, I want to implement BiPerm with strictly linear prover time, so that I can achieve optimal performance when using sparse polynomial commitment schemes.

#### Acceptance Criteria

1. WHEN arithmetizing 1_σ as product of two functions THEN the system SHALL compute 1̃_σ(X,Y) = 1̃_{σ_L}(X,Y_L) · 1̃_{σ_R}(X,Y_R)

2. WHEN splitting Y into halves THEN the system SHALL define Y_L := Y_{[1:μ/2]} and Y_R := Y_{[μ/2+1:μ]}

3. WHEN computing σ_L(X) THEN the system SHALL extract first μ/2 bits of σ(X) mapping B^μ → B^{μ/2}

4. WHEN computing σ_R(X) THEN the system SHALL extract last μ/2 bits of σ(X) mapping B^μ → B^{μ/2}

5. WHEN running BiPerm sumcheck THEN the system SHALL prove ∑_{x∈B^μ} f(x) · 1̃_{σ_L}(x,α_L) · 1̃_{σ_R}(x,α_R) = g(α)

6. WHEN sumcheck has degree 3 in each variable THEN the system SHALL achieve soundness error O(μ/|F|) = O(log n/|F|)

7. WHEN preprocessing 1̃_{σ_L} and 1̃_{σ_R} THEN the system SHALL commit to polynomials of size n^{1.5} with n non-zero entries

8. WHEN evaluating 1̃_{σ_L}(X,α_L) for all X ∈ B^μ THEN the system SHALL compute in O(√n + n) = O(n) time using lookup table

9. WHEN prover performs sumcheck rounds THEN the system SHALL execute O(n) field operations total

10. WHEN verifier queries oracles THEN the system SHALL query [[f]], [[g]], [[1̃_{σ_L}]], [[1̃_{σ_R}]] each once

11. WHEN compiling with sparse PCS (Dory, KZH, Hyrax) THEN the system SHALL achieve O(n) preprocessing and O(√n) opening cost

12. WHEN using hash-based PCS THEN the system SHALL incur n^{1.5} preprocessing cost but O(n) proving cost


### ### 5: MulPerm Protocol - Universal Permutation Check

**User Story:** As a protocol designer, I want to implement MulPerm that works with any polynomial commitment scheme, so that I can achieve near-linear prover time without PCS restrictions.

#### Acceptance Criteria

1. WHEN setting group parameter ℓ THEN the system SHALL choose ℓ = √μ = √(log n) to balance first and second sumcheck costs

2. WHEN arithmetizing 1_σ into ℓ parts THEN the system SHALL compute 1̃_σ(X,Y) = ∏_{j=1}^ℓ 1̃_j(X,Y^{(j)})

3. WHEN defining interval I_j THEN the system SHALL set I_j = [j' + 1, j' + μ/ℓ] where j' = (j-1)μ/ℓ

4. WHEN computing partial product p(x,⟨j⟩) THEN the system SHALL evaluate p(x,⟨j⟩) := ∏_{i=1}^{μ/ℓ} eq(α(⟨j'+i⟩), σ̃_{[μ]}(⟨j'+i⟩,x))

5. WHEN computing MLE p̃(x*,j*) THEN the system SHALL compute p̃(x*,j*) = ∑_{x∈B^μ,j∈[ℓ]} eq((x,⟨j⟩),(x*,j*)) · p(x,⟨j⟩)

6. WHEN running first sumcheck THEN the system SHALL prove ∑_{x∈B^μ} f(x) ∏_{j∈[ℓ]} p̃(x,⟨j⟩) = g(α)

7. WHEN first sumcheck completes THEN the system SHALL reduce to ℓ claims p̃(β,⟨j⟩) = P_j for j ∈ [ℓ] and random β ∈ F^μ

8. WHEN verifier samples t ∈ F^{log ℓ} THEN the system SHALL compute S_{p̃} ← ∑_{j∈[ℓ]} eq(t,⟨j⟩) · P_j

9. WHEN running second sumcheck THEN the system SHALL prove ∑_{x∈B^μ,j∈[ℓ]} eq(β',x||⟨j⟩) · p(x,⟨j⟩) = S_{p̃} where β' = β||t

10. WHEN computing p̃ evaluations over B^{μ+log ℓ} THEN the system SHALL use bucketing algorithm with o(n) field operations

11. WHEN bucketing in round k THEN the system SHALL group by 2^{μ/ℓ} possible polynomial identities for each eq(α_i, σ̃_i(X))

12. WHEN switching from bucketing to direct computation THEN the system SHALL switch at round k' = log ℓ where costs balance

13. WHEN prover performs all operations THEN the system SHALL execute n · Õ(√log n) total field operations

14. WHEN achieving soundness THEN the system SHALL have error O(μ^{1.5}/|F|) = polylog(n)/|F|

15. WHEN preprocessing σ̃_{[μ]} THEN the system SHALL commit to polynomial of size n log n mapping to {0,1}

16. WHEN compiling with any PCS THEN the system SHALL work with KZG, FRI, Ligero, STIR, WHIR, or any other scheme


### ### 6: Bucketing Algorithm for Efficient Sumcheck

**User Story:** As an optimization engineer, I want to implement the bucketing algorithm, so that I can reduce prover cost from superlinear to near-linear in the second sumcheck.

#### Acceptance Criteria

1. WHEN computing round polynomial in second sumcheck THEN the system SHALL observe that each eq(σ̃_i(X),y_i) takes only 4 possible forms: X, 1-X, 1, or 0

2. WHEN round k has formal variable X THEN the system SHALL compute that p̃(X,x',y_i) can take at most 4^{μ/ℓ} possible polynomial identities

3. WHEN bucketing in round k THEN the system SHALL precompute all 2^{2^k μ/ℓ} distinct polynomial identities

4. WHEN grouping evaluation points THEN the system SHALL partition {x' ∈ B^{μ+log ℓ-k}} by which identity p̃(X,x') matches

5. WHEN computing round polynomial u_k(X) THEN the system SHALL compute u_k(X) = ∑_i id_i · ∑_{x'∈bucket_i} eq((γ,X,x'),β')

6. WHEN bucketing costs exceed direct computation THEN the system SHALL switch algorithms at round k' = log ℓ

7. WHEN computing bucketing cost for round k THEN the system SHALL require (μ/ℓ+1)(μ/ℓ+2)·2^{2^k μ/ℓ}·ℓ field multiplications

8. WHEN computing direct cost for round k THEN the system SHALL require (μ/ℓ+2)² · ℓ·2^{μ+log ℓ-k} field multiplications

9. WHEN k < log ℓ THEN the system SHALL use bucketing algorithm with cost O(μ²/ℓ)·2^{2^k μ/ℓ}

10. WHEN k ≥ log ℓ THEN the system SHALL use direct computation with cost O(n·μ²/ℓ²)

11. WHEN collapsing evaluation tables after round log ℓ-1 THEN the system SHALL compute σ̃(⟨i⟩,(γ,x)) for all i ∈ [μ] using ℓ·2^ℓ operations

12. WHEN summing all round costs THEN the system SHALL achieve total n·Õ(μ/ℓ) + ℓ·2^ℓ field operations


### ### 7: Prover-Provided Permutation

**User Story:** As a memory-checking protocol developer, I want to support prover-provided permutations, so that I can handle dynamic permutations not known at preprocessing time.

#### Acceptance Criteria

1. WHEN permutation σ is not preprocessed THEN the system SHALL allow prover to compute and commit to σ̃_{[μ]} during runtime

2. WHEN prover provides σ THEN the system SHALL additionally prove that σ is a valid permutation on B^μ

3. WHEN proving σ is permutation THEN the system SHALL have prover commit to inverse τ̃_{[μ]} where τ = σ^{-1}

4. WHEN verifying permutation property THEN the system SHALL prove τ(σ(y)) = y for all y ∈ B^μ via sumcheck

5. WHEN reducing inverse check to sumcheck THEN the system SHALL prove ∑_{x∈B^μ} x · 1̃_σ(x,α) = τ̃(α)

6. WHEN proving σ maps to binaries THEN the system SHALL verify σ̃_{[μ]}(i,x) ∈ {0,1} for all x ∈ B^μ, i ∈ [μ]

7. WHEN checking binary constraint THEN the system SHALL prove ∑_{x∈B^μ,i∈[μ]} eq((x,⟨i⟩),s) · σ̃_{[μ]}(i,x)(1-σ̃_{[μ]}(i,x)) = 0

8. WHEN computing binary check sumcheck THEN the system SHALL use bucketing with parameter b = log μ' - k - 2 for round k

9. WHEN folding h^{(b)} in binary check THEN the system SHALL compute h^{(b)}(x',s'') recursively over b rounds

10. WHEN prover performs binary check THEN the system SHALL execute n·o(log log n) field operations

11. WHEN batching inverse and permutation checks THEN the system SHALL use random linear combination f'(y) = y + R·f(y), g'(y) = τ(y) + R·g(y)

12. WHEN proving batched claim THEN the system SHALL verify f'(y) = g'(σ(y)) for all y ∈ B^μ with single MulPerm invocation

13. WHEN total soundness is computed THEN the system SHALL achieve O(polylog n/|F|) error for prover-provided permutation


### ### 8: Lookup Arguments

**User Story:** As a SNARK system builder, I want to implement lookup arguments for range proofs and table lookups, so that I can efficiently prove witness values exist in preprocessed tables.

#### Acceptance Criteria

1. WHEN defining lookup relation R_LKUP THEN the system SHALL verify f(ρ(x)) = g(x) for all x ∈ B^μ where ρ: B^μ → B^κ

2. WHEN ρ is non-injective map THEN the system SHALL support lookups where multiple witness values map to same table entry

3. WHEN table has size T = 2^κ THEN the system SHALL represent table as multilinear polynomial f ∈ F_κ^{(≤1)}

4. WHEN witness has size n = 2^μ THEN the system SHALL represent witness as multilinear polynomial g ∈ F_μ^{(≤1)}

5. WHEN reducing lookup to sumcheck THEN the system SHALL add outer sum ∑_{x∈B^μ} eq(x,s)g(x) = ∑_{y∈B^κ} f(y) ∑_{x∈B^μ} eq(x,s)1̃_ρ(x,y)

6. WHEN running outer sumcheck over y THEN the system SHALL compute prover message for y ∈ I_ρ where I_ρ is image of ρ

7. WHEN T ≤ n THEN the system SHALL execute outer sumcheck in O(n) field operations

8. WHEN T > n THEN the system SHALL execute outer sumcheck in O(n(κ-μ)) = O(n(log T - log n)) field operations

9. WHEN outer sumcheck completes THEN the system SHALL reduce to claim f(α) ∑_{x∈B^μ} eq(x,s)·1̃_ρ(x,α) = S'

10. WHEN running inner sumcheck THEN the system SHALL use MulPerm with ℓ = √κ to prove ∑_{x∈B^μ} eq(x,s)·1̃_ρ(x,α) = S'/f(α)

11. WHEN T < 2^{(1-ε)μ²} for constant ε > 0 THEN the system SHALL achieve prover cost n·Õ(√log T) field operations

12. WHEN n < T < n^{log n} THEN the system SHALL achieve prover cost O(n(log T - log n)) field operations

13. WHEN table is structured THEN the system SHALL evaluate table MLE efficiently, e.g., range table t(X) = ∑_{i=0}^{log T-1} X_i·2^i in O(log T) time

14. WHEN achieving soundness THEN the system SHALL have error polylog(n+T)/|F|

15. WHEN comparing to other lookups THEN the system SHALL be first with polylogarithmic soundness error


### ### 9: Prover-Provided Lookup

**User Story:** As a range proof implementer, I want to support prover-provided lookup maps, so that I can prove witness values are in table without preprocessing the map.

#### Acceptance Criteria

1. WHEN lookup map ρ is not preprocessed THEN the system SHALL allow prover to compute and commit to ρ̃_{[κ]} during runtime

2. WHEN prover provides ρ THEN the system SHALL prove ρ̃_{[κ]} maps to {0,1} over B^{μ+log κ}

3. WHEN checking binary constraint for lookup THEN the system SHALL prove ∑_{x∈B^μ,i∈[κ]} eq((x,⟨i⟩),s)·ρ̃_{[κ]}(i,x)(1-ρ̃_{[κ]}(i,x)) = 0

4. WHEN T ≤ n THEN the system SHALL execute binary check in n·o(log log n) field operations

5. WHEN T > n THEN the system SHALL execute binary check in o(n·κ/μ) = o(n log n) field operations

6. WHEN binary check cost is computed THEN the system SHALL ensure it does not dominate total lookup argument cost

7. WHEN prover-provided lookup is complete THEN the system SHALL achieve same asymptotic costs as preprocessed lookup

8. WHEN soundness is analyzed THEN the system SHALL maintain polylog(n+T)/|F| soundness error


### ### 10: Polynomial Commitment Scheme Integration

**User Story:** As a cryptographic engineer, I want to compile PIOPs with various polynomial commitment schemes, so that I can deploy the protocol with different security assumptions and performance tradeoffs.

#### Acceptance Criteria

1. WHEN compiling PIOP to argument THEN the system SHALL replace oracles with polynomial commitments using PCS Γ = (Setup, Commit, Open, Eval)

2. WHEN PCS has witness-extended emulation THEN the system SHALL ensure compiled protocol is secure argument of knowledge

3. WHEN batching polynomial openings THEN the system SHALL use random linear combination ∑_{i=1}^t α_i·f_i(X) at point x* equals ∑_{i=1}^t α_i·y_i

4. WHEN using homomorphic PCS THEN the system SHALL achieve cryptographic operations proportional to n+t not n·t for t polynomials

5. WHEN using hash-based PCS THEN the system SHALL commit to interleaved code with operations independent of t

6. WHEN compiling BiPerm with sparse PCS (Dory, KZH, Hyrax) THEN the system SHALL achieve O(n) preprocessing, O(√n) opening beyond evaluation

7. WHEN compiling BiPerm with Ligero THEN the system SHALL achieve n^{1.5} preprocessing, O(n) proving time

8. WHEN compiling BiPerm with KZG or FRI THEN the system SHALL incur n^{1.5} preprocessing and proving costs

9. WHEN compiling MulPerm with any PCS THEN the system SHALL work with KZG, Dory, FRI, Ligero, STIR, WHIR without restrictions

10. WHEN using KZG with MulPerm THEN the system SHALL perform nW multi-scalar multiplications in preprocessing, nF in proving

11. WHEN using Dory with MulPerm THEN the system SHALL perform nW MSMs in preprocessing, n^{0.5}F MSMs in proving

12. WHEN using FRI or Ligero with MulPerm THEN the system SHALL perform n hashes in preprocessing and proving

13. WHEN proof size is computed THEN the system SHALL achieve O(log n) proof size for MulPerm with any PCS

14. WHEN verifier time is computed THEN the system SHALL achieve O(log n) verification for BiPerm, O(2 log n) for MulPerm


### ### 11: HyperPlonk Integration

**User Story:** As a HyperPlonk developer, I want to replace the permutation check with BiPerm or MulPerm, so that I can achieve single-commitment SNARK with better soundness and efficiency.

#### Acceptance Criteria

1. WHEN integrating with HyperPlonk THEN the system SHALL replace existing permutation argument with BiPerm or MulPerm

2. WHEN using BiPerm in HyperPlonk THEN the system SHALL achieve |w| commitment operations, n field operations, log(n) verifier time

3. WHEN using MulPerm in HyperPlonk THEN the system SHALL achieve |w| commitment operations, n·Õ(√log n) field operations, log(n) verifier time

4. WHEN batching sumchecks THEN the system SHALL combine permutation check sumcheck with gate constraint sumcheck

5. WHEN witness is sparse or low-weight THEN the system SHALL leverage PCS properties to reduce commitment cost

6. WHEN comparing to Quarks-style HyperPlonk THEN the system SHALL commit to |w| instead of 2n F elements

7. WHEN comparing to HyperPlonk sumcheck (3.6) THEN the system SHALL improve prover time from n·Õ(log n) to n or n·Õ(√log n)

8. WHEN soundness is compared THEN the system SHALL improve from log²n/|F| to log n/|F| (BiPerm) or log^{1.5}n/|F| (MulPerm)

9. WHEN single oracle to witness is achieved THEN the system SHALL query witness at single point after batching

10. WHEN lookup argument is replaced THEN the system SHALL commit to n elements of log T bit width instead of n+T full field elements


### ### 12: Spartan and SPARK Compiler Improvement

**User Story:** As a Spartan protocol developer, I want to improve the SPARK compiler using the new permutation check, so that I can achieve better soundness and lower verifier cost for R1CS proofs.

#### Acceptance Criteria

1. WHEN encoding sparse matrix M̃ ∈ {Ã,B̃,C̃} THEN the system SHALL use three polynomials val(), row(), col(): B^μ → B^s

2. WHEN evaluating M̃(x,y) THEN the system SHALL compute M̃(x,y) := ∑_{j∈B^μ} val̃(j)·1̃_{row}(j,x)·1̃_{col}(j,y)

3. WHEN verifier requests M̃(r_x,r_y) THEN the system SHALL prove via sumcheck M̃(r_x,r_y) := ∑_{j∈B^μ} val̃(j)·1̃_{row}(j,r_x)·1̃_{col}(j,r_y)

4. WHEN observing sumcheck structure THEN the system SHALL recognize it as preprocessed lookup argument

5. WHEN applying MulPerm to SPARK THEN the system SHALL achieve n·Õ(√log m) field operations where m is matrix dimension

6. WHEN comparing to GKR-based SPARK THEN the system SHALL reduce soundness error from n/|F| to polylog(n)/|F|

7. WHEN comparing to Quarks SPARK THEN the system SHALL reduce prover time while maintaining single witness commitment

8. WHEN verifier time is computed THEN the system SHALL achieve O(log n) instead of O(log²n) from GKR

9. WHEN proof size is computed THEN the system SHALL achieve O(log n) instead of O(log²n) from GKR

10. WHEN combining with Spartan or SuperSpartan THEN the system SHALL produce SNARK for R1CS/CCS with single witness oracle

11. WHEN final step requires val̃, row̃, col̃ evaluations THEN the system SHALL provide them as PCS openings


### ### 13: R1CS-Style GKR Protocol

**User Story:** As a GKR protocol designer, I want to implement R1CS-style GKR for non-uniform circuits, so that I can prove layered circuits with flexible structure without committing to intermediate values.

#### Acceptance Criteria

1. WHEN defining L-layered R1CS GKR circuit THEN the system SHALL specify layers where A^{(i)}z_i ∘ B^{(i)}z_i = z_{i+1}

2. WHEN matrices A^{(i)}, B^{(i)} ∈ F^{|z_{i+1}|×|z_i|} are given THEN the system SHALL preprocess their MLEs Ã^{(i)}, B̃^{(i)}

3. WHEN proving layer i correctness THEN the system SHALL verify ∑_{y∈B^{μ_i}} Ã^{(i)}(x,y)·z̃_i(y) · ∑_{y∈B^{μ_i}} B̃^{(i)}(x,y)·z̃_i(y) = z̃_{i+1}(x) for all x ∈ B^{μ_{i+1}}

4. WHEN reducing to single sumcheck THEN the system SHALL prove ∑_{x∈B^{μ_{i+1}}} eq(x,r)[∑_{y∈B^{μ_i}} Ã^{(i)}(x,y)·z̃_i(y)][∑_{y∈B^{μ_i}} B̃^{(i)}(x,y)·z̃_i(y)] = z̃_{i+1}(r)

5. WHEN sumcheck completes THEN the system SHALL have verifier check claimed evaluations A^{(i)}(r_x,r_y), B^{(i)}(r_x,r_y)

6. WHEN checking matrix evaluations THEN the system SHALL use lookup argument to prove M̃(r_x,r_y) := ∑_{j∈B^s} val̃(j)·1̃_{row}(j,r_x)·1̃_{col}(j,r_y)

7. WHEN applying MulPerm to matrix evaluation THEN the system SHALL achieve q·Õ(√log n) field operations where q = 2^s is number of nonzero entries

8. WHEN batching 2L matrix evaluation claims THEN the system SHALL use random linear combination to reduce to single sumcheck

9. WHEN comparing to standard GKR THEN the system SHALL support non-uniform circuits, arbitrary fan-in, and handle additions for free

10. WHEN comparing to LZ19 non-standard GKR THEN the system SHALL avoid tradeoff between fan-in and prover cost

11. WHEN example is inner product ⟨w,c⟩ THEN the system SHALL model as single layer with z_{in}=[1,w], A=[0,c]^T, B=[1,0^n]^T

12. WHEN prover commits THEN the system SHALL only commit to witness, not intermediate layer values


### ### 14: Soundness Analysis and Security

**User Story:** As a security analyst, I want rigorous soundness analysis for all protocols, so that I can ensure the protocols achieve claimed security guarantees.

#### Acceptance Criteria

1. WHEN analyzing Schwartz-Zippel soundness THEN the system SHALL achieve error μ/|F| for polynomial equality test over F^μ

2. WHEN analyzing sumcheck soundness THEN the system SHALL achieve error dμ/|F| for degree d polynomial over μ variables

3. WHEN combining Schwartz-Zippel and sumcheck THEN the system SHALL add soundness errors: δ_total = δ_SZ + δ_sumcheck

4. WHEN BiPerm soundness is computed THEN the system SHALL achieve O(μ/|F|) = O(log n/|F|)

5. WHEN MulPerm first sumcheck soundness is computed THEN the system SHALL achieve (ℓ+1)(μ+log ℓ)/|F|

6. WHEN MulPerm second sumcheck soundness is computed THEN the system SHALL achieve (μ/ℓ+1)(μ+log ℓ)/|F|

7. WHEN MulPerm total soundness is computed THEN the system SHALL achieve O(μ^{1.5}/|F|) = polylog(n)/|F|

8. WHEN n=2^{32} and |F|=2^{128} THEN the system SHALL improve soundness from 2^{-96} (product check) to 2^{-120} (MulPerm)

9. WHEN prover-provided permutation soundness is computed THEN the system SHALL achieve O(polylog n/|F|) including binary check

10. WHEN lookup soundness is computed THEN the system SHALL achieve polylog(n+T)/|F|

11. WHEN knowledge soundness is required THEN the system SHALL ensure extractor can recover committed polynomial from oracle queries

12. WHEN Fiat-Shamir is applied THEN the system SHALL ensure multi-round special soundness for non-interactive compilation

13. WHEN comparing to GKR-based approaches THEN the system SHALL avoid super-constant round protocols vulnerable to recent attacks


### ### 15: Performance Optimization Techniques

**User Story:** As a performance engineer, I want to implement all optimization techniques from the paper, so that I can achieve the claimed asymptotic and concrete performance.

#### Acceptance Criteria

1. WHEN computing equality polynomial eq(y_L,α_L) THEN the system SHALL evaluate at all y_L ∈ B^{μ/2} in O(2^{μ/2}) time using dynamic programming

2. WHEN computing round polynomial u_k(X) THEN the system SHALL use FFT to multiply polynomial evaluation lists in Õ(degree) time

3. WHEN prover sends degree d polynomial THEN the system SHALL send degree d-2 polynomial u'_k plus u_k(0) to reduce communication

4. WHEN verifier needs three evaluations THEN the system SHALL reconstruct u_k(0), u_k(1), u_k(α_k) from single query to u'_k

5. WHEN collapsing evaluation tables THEN the system SHALL fold tables after each sumcheck round to maintain O(2^{μ-k}) size

6. WHEN computing partial products p̃(x',⟨j⟩) THEN the system SHALL use bucketing to compute in o(n) time instead of nμ

7. WHEN bucketing identifies 2^{μ/ℓ} possible evaluations THEN the system SHALL precompute them once and lookup for each x

8. WHEN switching algorithms in second sumcheck THEN the system SHALL switch at k'=log ℓ where bucketing cost equals direct cost

9. WHEN computing collapsed tables THEN the system SHALL use Algorithm 11 with fewer than ℓ·2^ℓ field operations

10. WHEN batching multiple sumcheck instances THEN the system SHALL use random linear combination to reduce verification cost

11. WHEN batching polynomial openings THEN the system SHALL open t polynomials at same point with cost n+t not n·t

12. WHEN structured tables are used THEN the system SHALL exploit structure for O(log T) evaluation instead of O(T)

13. WHEN witness is sparse THEN the system SHALL use sparse PCS to reduce commitment cost proportional to sparsity

14. WHEN implementing in practice THEN the system SHALL use concrete optimizations like precomputation tables and SIMD operations


### ### 16: Algorithm Implementations

**User Story:** As an implementer, I want precise algorithm specifications, so that I can implement the protocols correctly with all details.

#### Acceptance Criteria

1. WHEN implementing Algorithm 1 (Naïve Sumcheck) THEN the system SHALL follow exact steps for degree-μ arithmetization baseline

2. WHEN implementing Algorithm 2 (BiPerm Sumcheck) THEN the system SHALL compute degree-3 sumcheck with 1̃_{σ_L} and 1̃_{σ_R}

3. WHEN implementing Algorithm 3 (MulPerm PIOP) THEN the system SHALL execute double-sumcheck with ComputePartialProducts, Sumcheck1, Sumcheck2

4. WHEN implementing Algorithm 4 (ComputePartialProducts) THEN the system SHALL compute p̃(x') for all x' ∈ B^{μ+log ℓ} using bucketing

5. WHEN implementing Algorithm 5 (First Sumcheck) THEN the system SHALL reduce ∑_{x∈B^μ} f(x)∏_{j∈[ℓ]} p̃(x,⟨j⟩) = S to ℓ claims

6. WHEN implementing Algorithm 6 (Bucketing) THEN the system SHALL compute round polynomial using precomputed identity buckets

7. WHEN implementing Algorithm 7 (Second Sumcheck) THEN the system SHALL prove ∑_{x∈B^μ,j∈[ℓ]} eq(β',x||⟨j⟩)·p(x,⟨j⟩) = S_{p̃}

8. WHEN implementing Algorithm 8 (PERM2) THEN the system SHALL handle prover-provided permutation with inverse check

9. WHEN implementing Algorithm 9 (BinMap) THEN the system SHALL prove σ̃_{[μ]} maps to binaries with optimized bucketing

10. WHEN implementing Algorithm 10 (Lookup) THEN the system SHALL execute outer sumcheck over table then inner sumcheck over witness

11. WHEN implementing Algorithm 11 (Collapse) THEN the system SHALL compute collapsed evaluation tables before algorithm switch

12. WHEN implementing Fold procedure THEN the system SHALL recursively fold evaluation tables over k rounds

13. WHEN implementing BinMapBucket THEN the system SHALL use parameter b = log μ' - k - 2 for efficient binary checking

14. WHEN all algorithms are implemented THEN the system SHALL match complexity bounds stated in theorems


### ### 17: Comparison with Existing Protocols

**User Story:** As a protocol evaluator, I want detailed comparisons with existing approaches, so that I can understand the improvements and tradeoffs.

#### Acceptance Criteria

1. WHEN comparing to ProdCheck THEN the system SHALL note it requires n+log n commitments, has n/|F| soundness, O(n) prover time

2. WHEN comparing to GKR-based permcheck THEN the system SHALL note it requires log²n rounds, has n/|F| soundness, O(log²n) verifier time

3. WHEN comparing to GKR-k hybrid THEN the system SHALL note it runs k GKR rounds then ProdCheck, achieving k·log n verifier time

4. WHEN comparing to HyperPlonk (3.8) THEN the system SHALL note it requires log²n commitments, has log²n/|F| soundness, n·Õ(log n) prover time

5. WHEN comparing to Naïve Perm THEN the system SHALL note it requires n² index size, has log n/|F| soundness, O(n) prover time

6. WHEN comparing to Shout THEN the system SHALL note BiPerm has same structure when d=2, but Shout lacks prover-provided permutation

7. WHEN comparing to Lasso THEN the system SHALL note MulLookup has better soundness, verifier time, proof size, fewer table restrictions

8. WHEN comparing to LogUp THEN the system SHALL note MulLookup commits to less additional information, has polylog soundness

9. WHEN comparing to Plookup THEN the system SHALL note MulLookup has better prover time and soundness error

10. WHEN comparing to Caulk/Baloo/cq/flookup THEN the system SHALL note those require trusted setup and pairings, are table-size independent

11. WHEN comparing proof sizes THEN the system SHALL show BiPerm and MulPerm achieve O(log n) vs O(log²n) for GKR-based

12. WHEN comparing verifier times THEN the system SHALL show BiPerm achieves log n, MulPerm achieves 2 log n vs log²n for GKR

13. WHEN comparing soundness THEN the system SHALL show improvement from n/|F| to polylog(n)/|F|

14. WHEN comparing PCS requirements THEN the system SHALL note BiPerm requires sparse PCS, MulPerm works with any PCS


### ### 18: Testing and Verification

**User Story:** As a quality assurance engineer, I want comprehensive testing requirements, so that I can verify correctness of all protocol components.

#### Acceptance Criteria

1. WHEN testing equality polynomial THEN the system SHALL verify eq(x,y)=1 iff x=y for all x,y ∈ B^μ with μ ≤ 10

2. WHEN testing multilinear extension THEN the system SHALL verify f̃(b) = f(b) for all b ∈ B^μ and f̃ is multilinear

3. WHEN testing sumcheck protocol THEN the system SHALL verify honest prover convinces verifier with probability 1

4. WHEN testing sumcheck soundness THEN the system SHALL verify malicious prover succeeds with probability ≤ dμ/|F|

5. WHEN testing BiPerm completeness THEN the system SHALL verify valid permutation always accepted

6. WHEN testing BiPerm soundness THEN the system SHALL verify invalid permutation rejected with high probability

7. WHEN testing MulPerm with various ℓ THEN the system SHALL verify correctness for ℓ ∈ {2, √μ, μ/2}

8. WHEN testing bucketing algorithm THEN the system SHALL verify it produces same result as direct computation

9. WHEN testing algorithm switch point THEN the system SHALL verify k'=log ℓ minimizes total cost

10. WHEN testing prover-provided permutation THEN the system SHALL verify non-permutation maps are rejected

11. WHEN testing lookup arguments THEN the system SHALL verify witness values not in table are rejected

12. WHEN testing with different PCS THEN the system SHALL verify compilation works with KZG, Dory, FRI, Ligero

13. WHEN testing performance THEN the system SHALL measure actual field operations and compare to theoretical bounds

14. WHEN testing integration THEN the system SHALL verify HyperPlonk and Spartan integration maintains correctness

15. WHEN testing edge cases THEN the system SHALL verify behavior for n=1, n=2, sparse witnesses, structured tables


### ### 19: Documentation and Specification

**User Story:** As a protocol user, I want comprehensive documentation, so that I can understand and correctly use the protocols.

#### Acceptance Criteria

1. WHEN documentation is provided THEN the system SHALL include mathematical definitions for all primitives

2. WHEN algorithms are documented THEN the system SHALL provide pseudocode matching paper algorithms exactly

3. WHEN complexity is documented THEN the system SHALL state prover time, verifier time, proof size, soundness for each protocol

4. WHEN parameters are documented THEN the system SHALL explain how to choose μ, ℓ, field size |F| for security level λ

5. WHEN PCS integration is documented THEN the system SHALL provide guidance on which PCS to use for different scenarios

6. WHEN examples are provided THEN the system SHALL include worked examples for small n (e.g., n=8, n=16)

7. WHEN API is documented THEN the system SHALL specify function signatures, input/output formats, error conditions

8. WHEN security is documented THEN the system SHALL explain soundness analysis, knowledge soundness, Fiat-Shamir security

9. WHEN optimizations are documented THEN the system SHALL explain bucketing, FFT, batching, table collapsing techniques

10. WHEN limitations are documented THEN the system SHALL state when BiPerm requires sparse PCS, when MulLookup table restrictions apply

11. WHEN comparisons are documented THEN the system SHALL provide tables comparing to ProdCheck, GKR, HyperPlonk, Lasso, LogUp

12. WHEN references are provided THEN the system SHALL cite all relevant papers with proper attribution


### ### 20: Implementation Architecture

**User Story:** As a software architect, I want clear architectural requirements, so that I can design a modular, maintainable implementation.

#### Acceptance Criteria

1. WHEN designing module structure THEN the system SHALL separate primitives, sumcheck, permutation checks, lookup arguments, PCS integration

2. WHEN implementing field operations THEN the system SHALL provide abstract field interface supporting addition, multiplication, inversion

3. WHEN implementing polynomial operations THEN the system SHALL provide multilinear polynomial evaluation, MLE computation, FFT

4. WHEN implementing sumcheck THEN the system SHALL provide generic sumcheck that works with any virtual polynomial

5. WHEN implementing BiPerm THEN the system SHALL depend only on sumcheck and equality polynomial primitives

6. WHEN implementing MulPerm THEN the system SHALL depend on sumcheck, bucketing algorithm, table collapsing

7. WHEN implementing PCS integration THEN the system SHALL provide adapter pattern for different PCS schemes

8. WHEN implementing optimizations THEN the system SHALL make them optional with feature flags for benchmarking

9. WHEN handling errors THEN the system SHALL provide clear error messages for invalid inputs, failed verifications

10. WHEN supporting multiple fields THEN the system SHALL work with prime fields, binary fields, extension fields

11. WHEN providing APIs THEN the system SHALL offer both low-level (algorithm-specific) and high-level (application-specific) interfaces

12. WHEN ensuring correctness THEN the system SHALL use type system to prevent misuse (e.g., dimension mismatches)


### REQUIREMENT  21: Non-Interactive (Fiat-Shamir) Protocol Transformation
User Story: As a SNARK developer, I want to convert the interactive protocols into a non-interactive proof system, so that proofs can be generated once and verified by anyone without further interaction.
Acceptance Criteria:
WHEN converting the interactive protocol to non-interactive THEN the system SHALL use the Fiat-Shamir transformation.
WHEN generating challenges THEN the system SHALL use a cryptographically secure hash function (e.g., BLAKE2s, Poseidon, Keccak) modeled as a random oracle.
WHEN managing the protocol state THEN the system SHALL use a transcript object to absorb all public data and prover messages (commitments, oracles, etc.).
WHEN challenges are required THEN the system SHALL squeeze them from the transcript, ensuring they are deterministically derived from the history of the interaction.
WHEN the final proof is constructed THEN the system SHALL include all prover messages necessary for the verifier to re-compute the challenges and run the verification logic.

### REQUIREMENT 22: Concrete Proof Serialization and Data Structures
User Story: As a user of the proving system, I want a well-defined format for proofs and public parameters, so that I can easily store, transmit, and use them across different systems.
Acceptance Criteria:
WHEN a proof is generated THEN the system SHALL serialize it into a single, contiguous byte array.
WHEN defining the proof structure THEN the system SHALL specify the exact layout, including all polynomial commitments, claimed evaluations, and opening proofs from the PCS.
WHEN handling public parameters (e.g., preprocessed permutation commitments) THEN the system SHALL define a clear serialization format.
WHEN choosing a serialization method THEN the system SHALL prioritize canonical and space-efficient encoding for all field and group elements.

### REQUIREMENT 23: Cryptographic Environment and Parameter Selection
User Story: As a security engineer, I want to define the complete cryptographic environment for a target security level, so that the implementation is secure and robust against known attacks.
Acceptance Criteria:
WHEN targeting a security level (e.g., 128-bit) THEN the system SHALL specify a corresponding finite field with sufficient size (e.g., a prime field with a modulus > 256 bits).
WHEN selecting a hash function for Fiat-Shamir THEN the system SHALL choose one that is secure and performant for the chosen field (e.g., an arithmetic-friendly hash like Poseidon).
WHEN a source of randomness is needed by the prover THEN the system SHALL use a cryptographically secure pseudo-random number generator (CSPRNG).
WHEN defining the complete parameter set THEN the system SHALL document the chosen field, elliptic curve (for KZG/Dory), hash function, and any other cryptographic primitive.
### REQUIREMENTS 24: Explicit Error Handling and Verification States
User Story: As a developer integrating the library, I want distinct error types and verification outcomes, so I can debug issues and provide clear feedback to users.
Acceptance Criteria:
WHEN verification fails THEN the system SHALL return a specific error indicating the failure point (e.g., SumcheckRoundFailure, FinalEvaluationMismatch, PcsVerificationFailure).
WHEN the prover receives invalid inputs THEN the system SHALL return an error instead of producing a proof.
WHEN a proof is malformed or cannot be deserialized THEN the system SHALL return an InvalidProofFormat error.
WHEN the final verifier output is generated THEN it SHALL be a boolean result (true for accept, false for reject), with errors being handled separately.
Missing Core Components for Implementation
From a software architecture perspective, the requirements imply the need for several core components that are not explicitly listed. Defining these upfront will lead to a more modular and maintainable implementation.
Transcript Manager:
Purpose: A crucial component for implementing the Fiat-Shamir transform.
Functionality: It should provide an interface to append prover messages (like commit(data)) and generate verifier challenges (like get_challenge()). It internally maintains the state of the hash function, ensuring a canonical transcript.
Domain and Evaluation Manager:
Purpose: To handle the mathematical domains and polynomial representations.
Functionality: Manages the boolean hypercube B^μ, computes multilinear extensions (MLEs), performs FFTs (if applicable for the chosen field), and implements the logic for collapsing evaluation tables during sumcheck protocols.
Prover/Verifier Orchestrators:
Purpose: High-level components that encapsulate the complete logic for a specific protocol (e.g., MulPermProver, MulPermVerifier).
Functionality: These orchestrators would drive the protocol flow, calling the Sumcheck component, the PCS, and the Transcript Manager in the correct sequence. This separates the high-level protocol logic from the underlying primitives.
Indexer (Setup Component):
Purpose: To handle any pre-computation or setup required by a protocol.
Functionality: For Fixed Permutation or Fixed Lookup protocols, this component is responsible for processing the permutation/table, computing its multilinear representation, and creating the necessary polynomial commitments. The output is a Proving Key and a Verification Key.
Cryptographic Primitives Module:
Purpose: An abstraction layer for the underlying cryptographic dependencies.
Functionality: Provides a consistent interface for finite field arithmetic, elliptic curve operations (if needed by the PCS), and the chosen hash function. This allows the core logic to be independent of the specific field or curve being used.