# Requirements Document: Small-Space zkVM Prover
## Complete Mathematical Specification

## Document Purpose and Scope

This document provides an EXHAUSTIVE specification for implementing a zkVM prover with significantly reduced memory footprint based on "Proving CPU Executions in Small Space" by Vineet Nair, Justin Thaler, and Michael Zhu (2025-611). 

**CRITICAL**: This specification captures EVERY mathematical formulation, EVERY equation, EVERY algorithm step, and EVERY technical detail from the source paper WITHOUT ANY OMISSION OR SIMPLIFICATION.

## Executive Summary

The system enables proving RISC-V CPU execution in small space without SNARK recursion, achieving O(K + T^(1/2)) or O(K + log T) space complexity while maintaining prover time within a factor of 2 of linear-space implementations.

**Key Achievement**: Jolt—an advanced, sum-check-based zkVM—can be implemented with significantly reduced memory footprint without relying on SNARK recursion and with only modest runtime overhead (potentially well below a factor of two). The key insight is that the fastest known methods of implementing zkVM provers are already naturally small-space, and hence the prover can be made small-space "almost for free".

## Requirements

### Requirement 1: Small-Space Sum-Check Protocol

**User Story:** As a zkVM developer, I want to implement sum-check proving in small space, so that memory usage is bounded by O(log T) rather than O(T).

#### Acceptance Criteria

1.1. WHEN the sum-check protocol is applied to a product of ℓ multilinear polynomials g₁,...,gℓ over n variables THEN the system SHALL implement Algorithm 1 (Small Space Sum-Check Prover) with space complexity O(n + ℓ²)

1.2. WHEN computing round i of sum-check THEN the system SHALL evaluate fᵢ(Xᵢ) = Σ_{x∈{0,1}^(n-i)} g(r₁,...,rᵢ₋₁,Xᵢ,x) using the formula:
```
gₖ(r₁,...,rᵢ₋₁,αₛ,tobits(m)) = (1-αₛ)·Σ_{j∈[0,2^(i-1)-1]} eq̃(r₁,...,rᵢ₋₁,tobits(j))·Aₖ[2^i·(2m)+j]
                                + αₛ·Σ_{j∈[0,2^(i-1)-1]} eq̃(r₁,...,rᵢ₋₁,tobits(j))·Aₖ[2^i·(2m+1)+j]
```

1.3. WHEN the prover has oracle access to g₁,...,gℓ that can be queried sequentially THEN the system SHALL compute each summand iteratively without storing intermediate arrays Aₖ,ᵢ

1.4. WHEN executing Algorithm 1 THEN the system SHALL perform O(ℓ²n·2ⁿ) field operations with time complexity O(ℓ²n·2ⁿ)

1.5. WHEN the multilinear extension eq̃(r₁,...,rᵢ₋₁,tobits(j)) is needed THEN the system SHALL compute it as:
```
eq̃(X,Y) = Π_{i=1}^n ((1-Xᵢ)(1-Yᵢ) + XᵢYᵢ)
```

### Requirement 2: Small-Value Sum-Check Optimization

**User Story:** As a performance engineer, I want to optimize sum-check for small field values, so that prover time is minimized when values fit in machine words.

#### Acceptance Criteria

2.1. WHEN all values g₁(x),...,gℓ(x) for x∈{0,1}ⁿ reside in subset B={0,1,...,2³²-1} of large field F THEN the system SHALL use Algorithm 3 from [BDT24] for the first several rounds

2.2. WHEN computing round i with i≤n/2 THEN the system SHALL maintain array C storing g₁(x)·g₂(x') for pairs x,x'∈{0,1}ⁿ where last i bits differ, requiring O(2ⁱ) space

2.3. WHEN computing round i THEN the system SHALL maintain array E storing {eq̃(rᵢ₋₁,y₁)·eq̃(rᵢ₋₁,y₂)}_{y₁,y₂∈{0,1}ⁱ} requiring O(2^(2i)) space

2.4. WHEN computing fᵢ(2) in round i THEN the system SHALL use the formula:
```
fᵢ(2) = Σ_{x∈{0,1}^(n-i)} Σ_{y₁,y₂∈{0,1}^(i+1)} eq̃(r₁,y₁)·eq̃(r₁,y₂)·
        (4·g₁(y₁,1,x)·g₂(y₂,1,x) - 2·g₁(y₁,1,x)·g₂(y₂,0,x) - 
         2·g₁(y₁,0,x)·g₂(y₂,1,x) + g₁(y₁,0,x)·g₂(y₂,0,x))
```

2.5. WHEN approximately n/2 rounds have passed THEN the system SHALL switch to the standard linear-time sum-check algorithm to minimize total field operations

2.6. WHEN using small-value optimization THEN the system SHALL compute array C on-the-fly by querying oracles to g₁ and g₂, requiring O(2ⁱ) space at round i instead of O(2ⁿ)

### Requirement 3: Streaming Witness Generation

**User Story:** As a zkVM implementer, I want to generate execution traces on-demand, so that memory usage is minimized during proving.

#### Acceptance Criteria

3.1. WHEN executing a RISC-V program with T cycles THEN the system SHALL generate witness vectors w₁,...,wₖ∈F^T by computing entries sequentially as the program executes

3.2. WHEN computing the j-th slice of witness w THEN the system SHALL require O(1) time and O(1) words of space beyond the K words needed to run the VM

3.3. WHEN witness generation is needed multiple times THEN the system SHALL store checkpoints at fixed intervals to enable parallel regeneration

3.4. WHEN M threads are available THEN the system SHALL regenerate witness chunks in parallel achieving up to factor-M speedup

3.5. WHEN witness generation accounts for under 5% of total prover time for single execution THEN the system SHALL ensure repeated generation (up to log K + (1/2)·log T ≈ 40 times) increases total parallel runtime by less than 15%

### Requirement 4: Spartan for Uniform R1CS

**User Story:** As a constraint system developer, I want to prove R1CS satisfaction in small space, so that Jolt's uniform constraints can be verified efficiently.

#### Acceptance Criteria

4.1. WHEN proving R1CS satisfaction with matrices A,B,C∈F^(m×n) and witness w∈F^(n-1) THEN the system SHALL verify (A·u)◦(B·u)=C·u where u=(1,w) and ◦ denotes component-wise product

4.2. WHEN Jolt has β constraints per CPU cycle and T total cycles THEN the system SHALL handle m=β·T total constraints with block-diagonal structure

4.3. WHEN computing h̃_A(Y)=Σ_{x∈{0,1}^(log n)} Ã(Y,x)·ũ(x) THEN the system SHALL stream the computation by generating witness slices on-demand

4.4. WHEN matrices A,B,C have block-diagonal structure with constant-sized blocks THEN the system SHALL compute Az, Bz, Cz by streaming z while executing the VM

4.5. WHEN proving polynomial q(S)=Σ_{y∈{0,1}^(log m)} eq̃(S,y)·(h̃_A(y)·h̃_B(y)-h̃_C(y)) is zero THEN the system SHALL apply sum-check protocol with small-space prover

4.6. WHEN handling program counter (pc) and next program counter (pcnext) THEN the system SHALL use virtual polynomial technique where:
```
p̃cnext(r) = Σ_{j∈{0,1}^(log T)} s̃hift(r,j)·p̃c(j)
```
with shift(i,j)=1 if val(i)=val(j)+1, else 0

4.7. WHEN evaluating shift function at random point THEN the system SHALL compute it in O(log T) space and time using the formula from [STW23, Theorem 2]

### Requirement 5: Shout Protocol for Read-Only Memory

**User Story:** As a memory-checking implementer, I want to verify read-only memory accesses in small space, so that instruction execution and bytecode lookups are proven efficiently.

#### Acceptance Criteria

5.1. WHEN read-only memory M has size K and T reads are performed THEN the system SHALL commit to multilinear extension r̃a of vector ra with length T·K using one-hot encoding

5.2. WHEN the k-th memory cell is read THEN the system SHALL represent it as unit vector eₖ∈{0,1}^K where k-th entry equals 1

5.3. WHEN computing return value r̃v(r) for point r∈F^(log T) THEN the system SHALL apply sum-check to:
```
r̃v(r) = Σ_{(k,j)∈{0,1}^(log K)×{0,1}^(log T)} eq̃(r,j)·r̃a(k,j)·M̃(k)
```

5.4. WHEN verifying addresses are unit vectors THEN the system SHALL invoke sum-check twice: once for Booleanity-checking (all entries in {0,1}) and once for Hamming-weight-one-checking

5.5. WHEN using dimension parameter d>1 THEN the system SHALL replace r̃a(k,j) with Π_{i=1}^d r̃aᵢ(kᵢ,j) where k=(k₁,...,kₐ) and each kᵢ has log(K)/d variables

5.6. WHEN d is set as constant THEN the system SHALL ensure Shout prover runs in time O(T) with space O(T^(1/2))

5.7. WHEN lookup table M̃ can be evaluated by verifier in O(log K) time THEN the system SHALL not require explicit commitment to M̃

### Requirement 6: Twist Protocol for Read/Write Memory

**User Story:** As a memory-checking implementer, I want to verify read/write memory operations in small space, so that register and RAM accesses are proven efficiently.

#### Acceptance Criteria

6.1. WHEN T read and T write operations are interleaved THEN the system SHALL commit to r̃a (read addresses), w̃a (write addresses), and w̃v (write values)

6.2. WHEN computing increment vector Ĩnc THEN the system SHALL ensure Ĩnc(j) equals w̃v(j) minus the value stored at relevant cell at time j

6.3. WHEN applying read-checking sum-check THEN the system SHALL compute:
```
Σ_{(k,j)∈{0,1}^(log K)×{0,1}^(log T)} eq̃(r,j)·r̃a(k,j)·M̃(k,j)
```
where r∈F^(log T) is verifier's chosen point

6.4. WHEN applying write-checking sum-check THEN the system SHALL verify:
```
Σ_{(k,j)∈{0,1}^(log K)×{0,1}^(log T)} eq̃(r,j)·eq̃(r',k)·w̃a(k,j)·(w̃v(j)-M̃(k,j)) = 0
```
for random r,r' chosen by verifier

6.5. WHEN applying M̃-evaluation sum-check THEN the system SHALL compute:
```
M̃(r,r') = Σ_{j∈{0,1}^(log T)} Ĩnc(r,j)·L̃T(r',j)
```
where L̃T is multilinear extension of less-than function

6.6. WHEN using dimension parameter d THEN the system SHALL ensure Twist prover runs in time O(K+T log K) with space O(K^(1/d)·T^(1/2))

6.7. WHEN memory accesses are i-local (accessing cells accessed within last 2ⁱ cycles) THEN the system SHALL pay only O(i) field operations per access

### Requirement 7: Prefix-Suffix Inner Product Protocol

**User Story:** As a protocol designer, I want to compute inner products with structured vectors in small space, so that pcnext-evaluation and M̃-evaluation sum-checks are efficient.

#### Acceptance Criteria

7.1. WHEN computing Σ_{x∈{0,1}^(log N)} ũ(x)·ã(x) where ã has prefix-suffix structure THEN the system SHALL use the prefix-suffix inner product protocol

7.2. WHEN ã(x₁,...,x_{log N}) has prefix-suffix structure for cutoff i with k terms THEN it SHALL satisfy:
```
ã(x₁,...,x_{log N}) = Σ_{j=1}^k prefixⱼ(x₁,...,xᵢ)·suffixⱼ(xᵢ₊₁,...,x_{log N})
```

7.3. WHEN C divides log N and ã has prefix-suffix structure for cutoffs i=log(N)/C,...,(C-1)log(N)/C THEN the system SHALL use space O(k·C·N^(1/C))

7.4. WHEN u has sparsity m (m non-zero entries) THEN the system SHALL perform O(C·k·m) field multiplications

7.5. WHEN making C passes over vectors u and a THEN the system SHALL compute the inner product correctly with linear time per pass

### Requirement 8: Polynomial Commitment Schemes

**User Story:** As a cryptographic engineer, I want to commit to polynomials in small space, so that proof generation doesn't require storing entire commitment keys.

#### Acceptance Criteria

8.1. WHEN using Dory commitment scheme with Twist and Shout THEN the system SHALL store commitment key of size 2√(KT) group elements

8.2. WHEN prover space is O(√T) for polynomial of size T THEN the system SHALL implement Dory prover with no slowdown compared to linear-space implementation

8.3. WHEN using Hyrax commitment scheme THEN the system SHALL implement prover in space O(√T) with no time overhead

8.4. WHEN space as low as O(log T) is desired THEN the system SHALL adapt techniques from [BHR+20] achieving O(T log T) prover time

8.5. WHEN generating commitment key on-the-fly THEN the system SHALL evaluate cryptographic PRG and apply hash-to-curve procedure requiring O(λ) field operations per group element

8.6. WHEN hash-to-curve bottleneck is square root computation in F THEN the system SHALL account for O(log |F|)=O(λ) field operations per element

### Requirement 9: Space-Time Trade-offs

**User Story:** As a system architect, I want configurable space-time trade-offs, so that prover can be optimized for different deployment scenarios.

#### Acceptance Criteria

9.1. WHEN target space is O(K+log T) THEN the system SHALL achieve this for appropriate polynomial commitment schemes

9.2. WHEN target space is O(K+T^(1/2)) THEN the system SHALL provide simpler and faster prover implementation

9.3. WHEN enough sum-check rounds have passed that space requirement halves below target THEN the system SHALL switch from small-space to linear-time prover algorithm

9.4. WHEN K≥2²⁵ and T≤2³⁵ THEN the system SHALL recognize O(K+log T) and O(K+T^(1/2)) are equivalent up to constant factors

9.5. WHEN storing T^(1/2) field elements for T=2⁴⁰ THEN the system SHALL require only dozens of MBs versus 10+ GBs for recursion-based approaches

### Requirement 10: Integration with Jolt zkVM

**User Story:** As a Jolt developer, I want to integrate small-space proving into Jolt, so that the complete zkVM operates with reduced memory footprint.

#### Acceptance Criteria

10.1. WHEN Jolt prover uses Twist and Shout with K=2²⁵ and T=2³⁵ THEN the system SHALL perform approximately 900T field multiplications in linear-space mode

10.2. WHEN small-space implementation is used THEN the system SHALL increase field multiplications by approximately 12T log T ≈ 400T operations

10.3. WHEN 12T log T << 900T for realistic T values THEN the system SHALL demonstrate that quasilinear time with small constant is faster than linear time with large constant

10.4. WHEN Spartan prover performs 250T field operations in linear space THEN small-space SHALL add at most 40T additional operations

10.5. WHEN Shout for instruction execution performs 40T operations in linear space THEN small-space SHALL add at most 2T log T operations

10.6. WHEN Twist for registers performs 35T operations in linear space THEN small-space SHALL add at most 4T log T operations

10.7. WHEN Twist for RAM performs up to 150T operations in linear space THEN small-space SHALL add at most 4T log T operations

10.8. WHEN commitment costs are approximately 350T field operations THEN the system SHALL maintain this cost in small-space mode with O(√(KT)) space

### Requirement 11: Correctness Properties

**User Story:** As a verification engineer, I want formal correctness guarantees, so that small-space proving produces identical results to linear-space proving.

#### Acceptance Criteria

11.1. WHEN Algorithm 1 (Small Space Sum-Check) is executed THEN it SHALL produce identical prover messages to the standard linear-time algorithm

11.2. WHEN witness is regenerated from checkpoints THEN it SHALL be identical to originally generated witness

11.3. WHEN prefix-suffix inner product protocol is used THEN it SHALL compute the same sum as standard sum-check

11.4. WHEN small-value sum-check optimization is applied THEN it SHALL produce identical results to standard algorithm for all field values

11.5. WHEN switching between small-space and linear-space algorithms mid-protocol THEN the transition SHALL be seamless with no correctness impact

### Requirement 12: Performance Bounds

**User Story:** As a performance analyst, I want concrete performance bounds, so that deployment decisions can be made with confidence.

#### Acceptance Criteria

12.1. WHEN prover slowdown factor is measured THEN it SHALL be well under 2× for realistic T values (T≥2²⁰)

12.2. WHEN sparse sums are processed in early rounds THEN the system SHALL incur no time overhead for small-space operation

12.3. WHEN dense sums are processed in final log T rounds THEN the system SHALL incur time overhead only in these rounds

12.4. WHEN witness generation is repeated up to 40 times with 16 threads THEN parallel runtime SHALL increase by less than factor of 3

12.5. WHEN total witness generation time is under 5% of prover time THEN repeated generation SHALL add less than 15% to total time

12.6. WHEN using small-value optimization for first 8 rounds THEN the system SHALL achieve 2⁸=256-fold space reduction with minimal time overhead

### Requirement 13: Security Properties

**User Story:** As a security engineer, I want to maintain security guarantees, so that small-space proving doesn't compromise soundness.

#### Acceptance Criteria

13.1. WHEN sum-check soundness error is ℓ·n/|F| for standard algorithm THEN small-space SHALL maintain identical soundness

13.2. WHEN Fiat-Shamir transformation is applied THEN the system SHALL avoid recursion-related security concerns

13.3. WHEN algebraic hash functions are avoided THEN the system SHALL rely only on standard cryptographic assumptions

13.4. WHEN commitment scheme security is based on discrete logarithm THEN small-space SHALL not weaken this assumption

13.5. WHEN random oracle model security holds for non-recursive SNARK THEN small-space SHALL preserve this property

### Requirement 14: Implementation Constraints

**User Story:** As a software engineer, I want clear implementation guidelines, so that the system can be built correctly and efficiently.

#### Acceptance Criteria

14.1. WHEN implementing Algorithm 1 THEN the system SHALL use nested loops with outer loop over m∈{0,...,2^(n-i)-1} and inner loop over j∈{0,...,2^(i-1)-1}

14.2. WHEN storing intermediate values THEN the system SHALL use arrays of size O(ℓ²) for witness_eval and O(ℓ+1) for accumulator

14.3. WHEN querying oracles THEN the system SHALL compute indices as u_even=2^i·2m+j and u_odd=2^i·(2m+1)+j

14.4. WHEN computing multilinear extensions THEN the system SHALL use Fact 2.1: ũ(c,x)=(1-c)·ũ(0,x)+c·ũ(1,x)

14.5. WHEN implementing checkpointing THEN the system SHALL store VM state snapshots at intervals of T/M for M threads

14.6. WHEN dimension parameter d is chosen THEN it SHALL be set as small as possible subject to commitment key size or commitment time constraints

14.7. WHEN field F has size at least 2^λ for security parameter λ THEN the system SHALL ensure all operations are performed in this field

### Requirement 15: Testing and Validation

**User Story:** As a quality assurance engineer, I want comprehensive testing requirements, so that correctness can be verified.

#### Acceptance Criteria

15.1. WHEN comparing small-space and linear-space provers THEN they SHALL produce bit-identical proofs for same inputs

15.2. WHEN testing with T∈{2²⁰,2²⁵,2³⁰,2³⁵} THEN the system SHALL demonstrate space reduction and bounded time overhead

15.3. WHEN measuring memory usage THEN it SHALL be verified to be O(K+T^(1/2)) or O(K+log T) as configured

15.4. WHEN testing witness regeneration THEN checkpointed regeneration SHALL produce identical witnesses to original generation

15.5. WHEN testing prefix-suffix protocol THEN it SHALL correctly compute inner products for all valid prefix-suffix structured polynomials

15.6. WHEN testing small-value optimization THEN it SHALL correctly handle values in B={0,1,...,2³²-1} and switch to standard algorithm at appropriate round

15.7. WHEN testing Twist and Shout THEN they SHALL correctly verify all memory operations with small-space provers

15.8. WHEN testing Spartan THEN it SHALL correctly prove R1CS satisfaction with block-diagonal matrices in small space


## Mathematical Preliminaries and Notation

### Requirement 0: Field and Notation Definitions

**User Story:** As a cryptographic engineer, I want precise mathematical definitions, so that all operations are unambiguous.

#### Acceptance Criteria

0.1. WHEN working with finite fields THEN the system SHALL use F_p to denote a finite field of size p

0.2. WHEN security parameter is λ THEN the system SHALL work over field F_p of size at least 2^λ

0.3. WHEN the field size p is clear from context THEN the system MAY omit subscript and write F

0.4. WHEN counting operations THEN one operation in F_p SHALL be regarded as one time step

0.5. WHEN counting memory THEN one field element SHALL require one unit of memory

0.6. WHEN converting integers to binary THEN the system SHALL use tobits function where:
```
tobits: {0,1,...,2^n-1} → {0,1}^n
tobits(val(b₁,...,bₙ)) = (b₁,...,bₙ)
```
with b₁ as low-order bit (leftmost) and bₙ as high-order bit (rightmost)

0.7. WHEN converting binary to integers THEN the system SHALL use val function where:
```
val(b₁,...,bₙ) = Σᵢ₌₁ⁿ 2^(i-1) · bᵢ
```

0.8. WHEN computing multilinear extensions THEN for function f: {0,1}^n → F, the MLE f̃ SHALL be:
```
f̃(X₁,X₂,...,Xₙ) = Σ_{x∈{0,1}^n} f(x) · ∏ᵢ₌₁ⁿ ((1-Xᵢ)(1-xᵢ) + Xᵢ·xᵢ)
```

0.9. WHEN f̃ is the MLE THEN it SHALL be the unique multilinear polynomial such that f̃(y) = f(y) for all y ∈ {0,1}^n

0.10. WHEN given vector w ∈ F^(2^n) THEN the MLE w̃ SHALL satisfy w̃(tobits(i)) = wᵢ for i ∈ {0,1,...,2^n-1}

0.11. WHEN using multilinear polynomial ũ: F^n → F THEN for any c ∈ F and x ∈ F^(n-1):
```
ũ(c,x) = (1-c)·ũ(0,x) + c·ũ(1,x)
```

0.12. WHEN computing equality function MLE THEN for x,y ∈ {0,1}^n:
```
ẽq(X,Y) = ∏ᵢ₌₁ⁿ ((1-Xᵢ)(1-Yᵢ) + XᵢYᵢ)
```
which equals 1 if x=y and 0 otherwise

0.13. WHEN using inner product notation ⟨u,v⟩ for vectors u,v ∈ F^n THEN it SHALL denote:
```
⟨u,v⟩ = Σᵢ₌₁ⁿ uᵢ·vᵢ
```

0.14. WHEN using inner product notation ⟨u,g⟩ for u ∈ F^n and g ∈ G^n (group elements) THEN it SHALL denote multiscalar multiplication:
```
⟨u,g⟩ = Σᵢ₌₁ⁿ uᵢ·gᵢ
```
where sum denotes group addition and uᵢ·gᵢ denotes scalar multiplication



## Requirements

### Requirement 1: Small-Space Sum-Check Protocol (Algorithm 1)

**User Story:** As a zkVM developer, I want to implement sum-check proving in small space, so that memory usage is bounded by O(log T) rather than O(T).

#### Mathematical Foundation

The sum-check protocol verifies sums of the form:
```
v = Σ_{x∈{0,1}^n} g(x)
```
where g(X₁,...,Xₙ) = ∏_{k∈{1,...,ℓ}} gₖ(X₁,...,Xₙ) is a product of ℓ multilinear polynomials.

#### Acceptance Criteria

1.1. WHEN the sum-check protocol is applied to product of ℓ multilinear polynomials g₁,...,gℓ over n variables THEN the system SHALL implement Algorithm 1 (Small Space Sum-Check Prover) with space complexity O(n + ℓ²)

1.2. WHEN computing round i of sum-check THEN the prover SHALL send univariate polynomial fᵢ(Xᵢ) defined as:
```
f₁(X₁) = Σ_{x∈{0,1}^(n-1)} g(X₁,x)
fᵢ(Xᵢ) = Σ_{x∈{0,1}^(n-i)} g(r₁,...,rᵢ₋₁,Xᵢ,x) for i ∈ {2,...,n}
```

1.3. WHEN verifier checks round 1 THEN it SHALL verify v = f₁(0) + f₁(1)

1.4. WHEN verifier checks round i ∈ {2,...,n-1} THEN it SHALL verify fᵢ(rᵢ) = fᵢ₋₁(1) + fᵢ₋₁(0)

1.5. WHEN verifier checks final round THEN it SHALL verify g(r₁,...,rₙ) = fₙ(rₙ) by computing:
```
g(r₁,...,rₙ) = ∏_{k=1}^ℓ gₖ(r₁,...,rₙ)
```

1.6. WHEN computing gₖ(r₁,...,rᵢ₋₁,αₛ,tobits(m)) in round i THEN the system SHALL use Claim 3.2 formula:
```
gₖ(r₁,...,rᵢ₋₁,αₛ,tobits(m)) = 
  (1-αₛ)·Σ_{j∈[0,2^(i-1)-1]} ẽq(r₁,...,rᵢ₋₁,tobits(j))·Aₖ[2^i·(2m)+j]
  + αₛ·Σ_{j∈[0,2^(i-1)-1]} ẽq(r₁,...,rᵢ₋₁,tobits(j))·Aₖ[2^i·(2m+1)+j]
```

1.7. WHEN the prover has oracle access to g₁,...,gℓ that can be queried sequentially THEN the system SHALL compute each summand iteratively without storing intermediate arrays Aₖ,ᵢ

1.8. WHEN executing Algorithm 1 THEN the system SHALL perform O(ℓ²n·2ⁿ) field operations with time complexity O(ℓ²n·2ⁿ)

1.9. WHEN computing ẽq(r₁,...,rᵢ₋₁,tobits(j)) THEN the system SHALL use:
```
ẽq(X,Y) = ∏ᵢ₌₁ⁿ ((1-Xᵢ)(1-Yᵢ) + XᵢYᵢ)
```

1.10. WHEN implementing Algorithm 1 Step 7 THEN the system SHALL compute uₑᵥₑₙ = 2^i·2m + j with binary representation (j,0,tobits(m))

1.11. WHEN implementing Algorithm 1 Step 10 THEN the system SHALL compute uₒ𝒹𝒹 = 2^i·(2m+1) + j with binary representation (j,1,tobits(m))

1.12. WHEN implementing Algorithm 1 Step 14 THEN the system SHALL update witness_eval[k][s] by adding:
```
ẽq((r₁,...,rᵢ₋₁),tobits(j))·((1-αₛ)·Aₖ[uₑᵥₑₙ] + αₛ·Aₖ[uₒ𝒹𝒹])
```

1.13. WHEN implementing Algorithm 1 Step 19 THEN the system SHALL compute:
```
accumulator[s] += ∏_{k=1}^ℓ witness_eval[k][s]
```

1.14. WHEN Algorithm 1 completes round i THEN accumulator[s] SHALL equal:
```
fᵢ(αₛ) = Σ_{m=0}^{2^(n-i)-1} ∏_{k=1}^ℓ gₖ(r₁,...,rᵢ₋₁,αₛ,tobits(m))
```

1.15. WHEN sum-check has soundness error THEN it SHALL be at most ℓ·n/|F|

1.16. WHEN switching from small-space to linear-time algorithm THEN the system SHALL do so when enough rounds have passed that space requirement halves below target



### Requirement 2: Small-Value Sum-Check Optimization (Algorithm 3 from BDT24)

**User Story:** As a performance engineer, I want to optimize sum-check for small field values, so that prover time is minimized when values fit in machine words.

#### Mathematical Foundation

When all values g₁(x),...,gℓ(x) for x∈{0,1}ⁿ reside in subset B={0,1,...,2³²-1} of large field F, or when working over field of small characteristic with values in small subfield.

#### Acceptance Criteria

2.1. WHEN all values g₁(x),...,gℓ(x) for x∈{0,1}ⁿ reside in subset B={0,1,...,2³²-1} of large field F THEN the system SHALL use Algorithm 3 from [BDT24] for the first several rounds

2.2. WHEN computing round i with i≤n/2 THEN the system SHALL maintain array C storing g₁(x)·g₂(x') for pairs x,x'∈{0,1}ⁿ where last i bits differ, requiring O(2ⁱ) space

2.3. WHEN computing round i THEN the system SHALL maintain array E storing {ẽq(rᵢ₋₁,y₁)·ẽq(rᵢ₋₁,y₂)}_{y₁,y₂∈{0,1}ⁱ} requiring O(2^(2i)) space

2.4. WHEN computing f₁(0) and f₁(1) in round 1 THEN the system SHALL use:
```
f₁(0) = Σ_{i∈{0,...,2^(n-1)-1}} C[2·i]
f₁(1) = Σ_{i∈{0,...,2^(n-1)-1}} C[2·i+1]
```

2.5. WHEN computing f₁(2) in round 1 THEN the system SHALL use:
```
f₁(2) = Σ_{i∈{0,...,2^(n-1)-1}} 4·C[2·i+1] 
        - Σ_{i∈{0,...,2^(n-1)-1}} 2(A₁(2·i)·A₂(2·i+1) + A₁(2·i+1)·A₂(2·i))
        + Σ_{i∈{0,...,2^(n-1)-1}} C[2·i]
```

2.6. WHEN computing fᵢ(s) for s∈{0,1,2} in round i>1 THEN the system SHALL use:
```
fᵢ(s) = Σ_{x∈{0,1}^(n-i)} Σ_{y₁,y₂∈{0,1}ⁱ} ẽq(rᵢ₋₁,y₁)·ẽq(rᵢ₋₁,y₂)·g₁(y₁,s,x)·g₂(y₂,s,x)
```

2.7. WHEN computing fᵢ(2) in round i THEN the system SHALL use the formula:
```
fᵢ(2) = Σ_{x∈{0,1}^(n-i)} Σ_{y₁,y₂∈{0,1}^(i+1)} ẽq(r₁,y₁)·ẽq(r₁,y₂)·
        (4·g₁(y₁,1,x)·g₂(y₂,1,x) - 2·g₁(y₁,1,x)·g₂(y₂,0,x) - 
         2·g₁(y₁,0,x)·g₂(y₂,1,x) + g₁(y₁,0,x)·g₂(y₂,0,x))
```

2.8. WHEN approximately n/2 rounds have passed THEN the system SHALL switch to the standard linear-time sum-check algorithm to minimize total field operations

2.9. WHEN using small-value optimization THEN the system SHALL compute array C on-the-fly by querying oracles to g₁ and g₂, requiring O(2ⁱ) space at round i instead of O(2ⁿ)

2.10. WHEN computing array E in round i THEN the system SHALL store:
```
E = {ẽq(rᵢ₋₁,0)·ẽq(rᵢ₋₁,0) = (1-rᵢ₋₁)²,
     ẽq(rᵢ₋₁,0)·ẽq(rᵢ₋₁,1) = (1-rᵢ₋₁)·rᵢ₋₁,
     ẽq(rᵢ₋₁,1)·ẽq(rᵢ₋₁,1) = rᵢ₋₁²}
```

2.11. WHEN round i is reached THEN array C SHALL contain g₁(x)·g₂(x') for all pairs x,x'∈{0,1}ⁿ where last i bits differ

2.12. WHEN using small-value optimization for first 8 rounds THEN the system SHALL achieve 2⁸=256-fold space reduction with minimal time overhead

2.13. WHEN field operations are over small field THEN machine multiplications SHALL be used instead of full field multiplications

2.14. WHEN switching to linear-time algorithm THEN the system SHALL do so when cost of maintaining E exceeds benefit of small-value optimization



### Requirement 3: Streaming Witness Generation

**User Story:** As a zkVM implementer, I want to generate execution traces on-demand, so that memory usage is minimized during proving.

#### Acceptance Criteria

3.1. WHEN executing a RISC-V program with T cycles THEN the system SHALL generate witness vectors w₁,...,wₖ∈F^T by computing entries sequentially as the program executes

3.2. WHEN computing the j-th slice of witness w THEN the system SHALL require O(1) time and O(1) words of space beyond the K words needed to run the VM

3.3. WHEN witness generation is needed multiple times THEN the system SHALL store checkpoints at fixed intervals to enable parallel regeneration

3.4. WHEN M threads are available THEN the system SHALL regenerate witness chunks in parallel achieving up to factor-M speedup

3.5. WHEN witness generation accounts for under 5% of total prover time for single execution THEN the system SHALL ensure repeated generation (up to log K + (1/2)·log T ≈ 40 times) increases total parallel runtime by less than 15%

3.6. WHEN witness vector w is constructed THEN it SHALL interleave k different vectors w₁,...,wₖ∈F^T as:
```
w = {wᵢ,ⱼ}_{i∈{0,...,k-1}, j∈{0,...,T-1}}
```

3.7. WHEN computing j-th slice of w THEN it SHALL consist of positions (j·k,...,(j+1)·k-1) of w

3.8. WHEN executing CPU cycle j THEN the system SHALL compute j-th slice in O(1) space and time

3.9. WHEN checkpointing for parallel regeneration THEN the system SHALL store VM state snapshots at intervals of T/M for M threads

3.10. WHEN regenerating witness from checkpoint THEN each thread SHALL independently regenerate its assigned chunk

### Requirement 4: Spartan for Uniform R1CS

**User Story:** As a constraint system developer, I want to prove R1CS satisfaction in small space, so that Jolt's uniform constraints can be verified efficiently.

#### Mathematical Foundation

R1CS constraint system comprises three matrices A,B,C ∈ F^(m×n). Witness w ∈ F^(n-1) satisfies if u=(1,w) satisfies:
```
(A·u) ◦ (B·u) = C·u
```
where ◦ denotes component-wise product.

#### Acceptance Criteria

4.1. WHEN proving R1CS satisfaction with matrices A,B,C∈F^(m×n) and witness w∈F^(n-1) THEN the system SHALL verify (A·u)◦(B·u)=C·u where u=(1,w) and ◦ denotes component-wise product

4.2. WHEN Jolt has β constraints per CPU cycle and T total cycles THEN the system SHALL handle m=β·T total constraints with block-diagonal structure

4.3. WHEN computing h̃_A(Y)=Σ_{x∈{0,1}^(log n)} Ã(Y,x)·ũ(x) THEN the system SHALL stream the computation by generating witness slices on-demand

4.4. WHEN matrices A,B,C have block-diagonal structure with constant-sized blocks THEN the system SHALL compute Az, Bz, Cz by streaming z while executing the VM

4.5. WHEN proving polynomial q(S) is zero THEN the system SHALL apply sum-check protocol to:
```
q(S) = Σ_{y∈{0,1}^(log m)} ẽq(S,y)·(h̃_A(y)·h̃_B(y) - h̃_C(y))
```
where:
```
h̃_A(Y) = Σ_{x∈{0,1}^(log n)} Ã(Y,x)·ũ(x)
h̃_B(Y) = Σ_{x∈{0,1}^(log n)} B̃(Y,x)·ũ(x)
h̃_C(Y) = Σ_{x∈{0,1}^(log n)} C̃(Y,x)·ũ(x)
```

4.6. WHEN handling program counter (pc) and next program counter (pcnext) THEN the system SHALL use virtual polynomial technique where:
```
p̃cnext(r) = Σ_{j∈{0,1}^(log T)} s̃hift(r,j)·p̃c(j)
```
with shift function:
```
shift(i,j) = {1 if val(i) = val(j)+1
             {0 otherwise
```

4.7. WHEN evaluating shift function at random point THEN the system SHALL compute it in O(log T) space and time using formula:
```
s̃hift(r,j) = h(r,j) + g(r,j)
```
where:
```
h(r,j) = (1-j₁)r₁·ẽq(j₂,...,j_{log T}, r₂,...,r_{log T})
g(r,j) = Σ_{k=1}^{log(T)-1} (∏ᵢ₌₁ᵏ jᵢ·(1-rᵢ))·(1-j_{k+1})r_{k+1}·ẽq(j_{k+2},...,j_{log T}, r_{k+2},...,r_{log T})
```

4.8. WHEN executing first sum-check in Spartan THEN verifier SHALL sample random point r_s ∈ F^(log m) and verify:
```
0 = Σ_{y∈{0,1}^(log m)} ẽq(r_s,y)·(h̃_A(y)·h̃_B(y) - h̃_C(y))
```

4.9. WHEN executing second sum-check in Spartan THEN the system SHALL verify simultaneously:
```
h̃_A(r_y) = Σ_{x∈{0,1}^(log n)} Ã(r_y,x)·ũ(x)
h̃_B(r_y) = Σ_{x∈{0,1}^(log n)} B̃(r_y,x)·ũ(x)
h̃_C(r_y) = Σ_{x∈{0,1}^(log n)} C̃(r_y,x)·ũ(x)
```
using random linear combination

4.10. WHEN block-diagonal structure has O(1) non-zero entries per row THEN verifier SHALL compute Ã(r_y,r_x), B̃(r_y,r_x), C̃(r_y,r_x) in O(log T) time

4.11. WHEN using small-value sum-check in Spartan THEN all values in h_A, h_B, h_C SHALL be in {0,1,...,2^64-1} (mostly in {0,1,...,2^32-1})

4.12. WHEN linear-space Spartan prover runs THEN it SHALL perform approximately 250T field operations

4.13. WHEN small-space Spartan prover runs THEN it SHALL add at most 40T additional field operations



### Requirement 5: Shout Protocol for Read-Only Memory

**User Story:** As a memory-checking implementer, I want to verify read-only memory accesses in small space, so that instruction execution and bytecode lookups are proven efficiently.

#### Mathematical Foundation

Shout verifies T reads into read-only memory M of size K using one-hot encoding.

#### Acceptance Criteria

5.1. WHEN read-only memory M has size K and T reads are performed THEN the system SHALL commit to multilinear extension r̃a of vector ra with length T·K using one-hot encoding

5.2. WHEN the k-th memory cell is read THEN the system SHALL represent it as unit vector eₖ∈{0,1}^K where k-th entry equals 1

5.3. WHEN computing return value r̃v(r) for point r∈F^(log T) THEN the system SHALL apply sum-check to:
```
r̃v(r) = Σ_{(k,j)∈{0,1}^(log K)×{0,1}^(log T)} ẽq(r,j)·r̃a(k,j)·M̃(k)
```

5.4. WHEN verifying addresses are unit vectors THEN the system SHALL invoke sum-check twice:
- Once for Booleanity-checking (all entries in {0,1})
- Once for Hamming-weight-one-checking

5.5. WHEN using dimension parameter d>1 THEN the system SHALL replace r̃a(k,j) with:
```
∏ᵢ₌₁ᵈ r̃aᵢ(kᵢ,j)
```
where k=(k₁,...,k_d) and each kᵢ has log(K)/d variables

5.6. WHEN d is set as constant THEN the system SHALL ensure Shout prover runs in time O(T) with space O(T^(1/2))

5.7. WHEN lookup table M̃ can be evaluated by verifier in O(log K) time THEN the system SHALL not require explicit commitment to M̃

5.8. WHEN O(K+T) runtime is acceptable THEN the prover SHALL:
- Make single pass over read addresses with time O(T) and space O(K)
- Initialize data structure of size O(K) sufficient for first log K rounds
- Complete first log K rounds in time O(K)

5.9. WHEN computing final log T rounds of read-checking sum-check THEN the system SHALL compute:
```
Σ_{j∈{0,1}^(log T)} ẽq(r,j)·r̃a(r*,j)·M̃(r*)
```
where r* is randomness from first log K rounds

5.10. WHEN O(K+T) runtime is NOT acceptable THEN the system SHALL use sparse-dense sum-check or prefix-suffix inner product protocol with:
- For any C>1: time O(CK^(1/C) + CT)
- Space O(K^(1/C))
- C passes over input

5.11. WHEN Booleanity-checking sum-check is invoked THEN it SHALL verify all entries of committed addresses are in {0,1}

5.12. WHEN Hamming-weight-one-checking sum-check is invoked THEN it SHALL verify each address has exactly one entry equal to 1

5.13. WHEN dimension parameter d is chosen THEN it SHALL be set as small as possible subject to:
- Commitment key size constraints (for elliptic curve schemes)
- Commitment time constraints (for hashing-based schemes)

5.14. WHEN using Shout for instruction execution with K=2^64 THEN linear-space prover SHALL perform approximately 40T field multiplications

5.15. WHEN using small-space Shout for instruction execution THEN it SHALL add at most 2T log T field operations

5.16. WHEN using Shout for bytecode lookups with bytecode size << T THEN linear-space prover SHALL perform approximately 5T field operations

### Requirement 6: Twist Protocol for Read/Write Memory

**User Story:** As a memory-checking implementer, I want to verify read/write memory operations in small space, so that register and RAM accesses are proven efficiently.

#### Mathematical Foundation

Twist handles T read and T write operations interleaved, with all memory cells initialized to 0.

#### Acceptance Criteria

6.1. WHEN T read and T write operations are interleaved THEN the system SHALL commit to r̃a (read addresses), w̃a (write addresses), and w̃v (write values)

6.2. WHEN computing increment vector Ĩnc THEN the system SHALL ensure Ĩnc(j) equals:
```
Ĩnc(j) = w̃v(j) - (value stored at relevant cell at time j)
```
where relevant cell value is w̃v(j') for largest j'<j with w̃a(j')=w̃a(j), or 0 if no such j' exists

6.3. WHEN applying read-checking sum-check THEN the system SHALL compute:
```
Σ_{(k,j)∈{0,1}^(log K)×{0,1}^(log T)} ẽq(r,j)·r̃a(k,j)·M̃(k,j)
```
where r∈F^(log T) is verifier's chosen point

6.4. WHEN applying write-checking sum-check THEN the system SHALL verify:
```
Σ_{(k,j)∈{0,1}^(log K)×{0,1}^(log T)} ẽq(r,j)·ẽq(r',k)·w̃a(k,j)·(w̃v(j)-M̃(k,j)) = 0
```
for random r,r' chosen by verifier

6.5. WHEN applying M̃-evaluation sum-check THEN the system SHALL compute:
```
M̃(r,r') = Σ_{j∈{0,1}^(log T)} Ĩnc(r,j)·L̃T(r',j)
```
where L̃T is multilinear extension of less-than function:
```
LT(j,j') = {1 if val(j) < val(j')
           {0 otherwise
```

6.6. WHEN using dimension parameter d THEN the system SHALL ensure Twist prover runs in time O(K+T log K) with space O(K^(1/d)·T^(1/2))

6.7. WHEN memory accesses are i-local (accessing cells accessed within last 2ⁱ cycles) THEN the system SHALL pay only O(i) field operations per access

6.8. WHEN implementing read-checking and write-checking in first log K rounds THEN the prover SHALL:
- Make single pass over read and write operations per round
- Use O(K) space
- Use O(T) total time per round

6.9. WHEN implementing final log T rounds of read-checking and write-checking THEN the system SHALL:
- Use standard logarithmic-space sum-check proving algorithm (Theorem 3.3)
- Switch to standard linear-time algorithm when space requirement permits
- Achieve total time O(T log T) and space O(K + log T)

6.10. WHEN using Twist for RISC-V registers (32 registers) THEN linear-space prover SHALL perform approximately 35T field operations

6.11. WHEN using small-space Twist for registers THEN it SHALL add at most 4T log T field operations

6.12. WHEN using Twist for RAM with size K=2^25 THEN worst-case linear-space prover SHALL perform less than 150T field multiplications

6.13. WHEN using small-space Twist for RAM THEN it SHALL add at most 4T log T field operations

6.14. WHEN less-than function L̃T is needed THEN it SHALL be computed as:
```
L̃T(r',j) = L̃T(r'₁,j₁) + L̃T(r'₂,j₂)
```
where for log(T)/2 variables:
```
L̃T(r'₁,j₁) = (1-j₁)r'₁·ẽq(j₂,...,j_{log T/2}, r'₂,...,r'_{log T/2})
```



### Requirement 7: Prefix-Suffix Inner Product Protocol

**User Story:** As a protocol designer, I want to compute inner products with structured vectors in small space, so that pcnext-evaluation and M̃-evaluation sum-checks are efficient.

#### Mathematical Foundation (Definition A.1)

A multilinear polynomial ã(x₁,...,x_{log N}) has prefix-suffix structure for cutoff i with k terms if there exist multilinear polynomials prefix₁,...,prefixₖ: Fⁱ → F and suffix₁,...,suffixₖ: F^(log(N)-i) → F such that:
```
ã(x₁,...,x_{log N}) = Σⱼ₌₁ᵏ prefixⱼ(x₁,...,xᵢ)·suffixⱼ(xᵢ₊₁,...,x_{log N})
```

#### Acceptance Criteria

7.1. WHEN computing Σ_{x∈{0,1}^(log N)} ũ(x)·ã(x) where ã has prefix-suffix structure THEN the system SHALL use the prefix-suffix inner product protocol

7.2. WHEN ã(x₁,...,x_{log N}) has prefix-suffix structure for cutoff i with k terms THEN it SHALL satisfy:
```
ã(x₁,...,x_{log N}) = Σⱼ₌₁ᵏ prefixⱼ(x₁,...,xᵢ)·suffixⱼ(xᵢ₊₁,...,x_{log N})
```

7.3. WHEN C divides log N and ã has prefix-suffix structure for cutoffs i=log(N)/C,...,(C-1)log(N)/C THEN the system SHALL use space O(k·C·N^(1/C))

7.4. WHEN u has sparsity m (m non-zero entries) THEN the system SHALL perform O(C·k·m) field multiplications

7.5. WHEN making C passes over vectors u and a THEN the system SHALL compute the inner product correctly with linear time per pass

7.6. WHEN implementing Stage 1 of prefix-suffix protocol THEN the system SHALL build array Q where:
```
Q[y] = Σ_{x=(x₁,...,x_C)∈({0,1}^(log(N)/C))^C: x₁=y} ũ(x)·suffix(x₂,...,x_C)
```

7.7. WHEN implementing Stage 1 THEN the system SHALL also build array P of size N^(1/C) storing:
```
P[y] = prefix(y) for y ∈ {0,1}^(log(N)/C)
```

7.8. WHEN computing prover messages in Stage 1 rounds THEN they SHALL be identical to messages in sum-check applied to:
```
Σ_{y∈{0,1}^(log(N)/C)} P̃(y)·Q̃(y)
```

7.9. WHEN implementing Stage j>1 THEN for verifier challenges r=(r₁,...,r_{log(N)/C}) from previous stage, array Q SHALL store:
```
Q[y] = Σ_{x=(x₃,...,x_C)∈({0,1}^(log(N)/C))^(C-2)} ũ(r,y,x)·suffix(x)
```

7.10. WHEN implementing Stage j>1 THEN array P SHALL store:
```
P[y] = prefix(r,y) for y ∈ {0,1}^(log(N)/C)
```

7.11. WHEN total runtime is computed THEN aside from array initialization, prover SHALL spend O(C·N^(1/C)) time and space

7.12. WHEN initializing Q in stage j THEN the system SHALL evaluate ũ(r,y,x) and suffix(x) for fixed r as (y,x) ranges over {0,1}^(log(N)/C) × {0,1}^(log(N)-j·log(N)/C)

7.13. WHEN initializing Q THEN ũ(r,y,x) SHALL be computed for all relevant values in time O(j·N^(1/C) + m) and space O(C·N^(1/C)) where m is sparsity of u

7.14. WHEN applying to pcnext-evaluation sum-check THEN s̃hift(r,j) SHALL have prefix-suffix structure:
```
s̃hift(r,j) = prefix₁(j₁)·suffix₁(j₂) + prefix₂(j₁)·suffix₂(j₂)
```
where:
```
prefix₁(j₁) = s̃hift(r₁,j₁)
suffix₁(j₂) = ẽq(r₂,j₂)
prefix₂(j₁) = ∏_{ℓ=1}^{log(T)/2} (1-r_ℓ)·j_{1,ℓ}
suffix₂(j₂) = s̃hift(r₂,j₂)
```

7.15. WHEN applying to M̃-evaluation sum-check THEN L̃T(r',j) SHALL have prefix-suffix structure:
```
L̃T(r',j) = prefix₁(j₁)·suffix₁(j₂) + prefix₂(j₁)·suffix₂(j₂)
```
where:
```
prefix₁(j₁) = L̃T(r'₁,j₁)
suffix₁(j₂) = ẽq(r'₂,j₂)
prefix₂(j₁) = 1
suffix₂(j₂) = L̃T(r'₂,j₂)
```

7.16. WHEN computing ẽq(r₂,j₂) for all j₂∈{0,1}^(log(T)/2) THEN it SHALL be done in O(√T) time and O(√T) space via standard techniques

7.17. WHEN computing L̃T(r'₁,j₁) and L̃T(r'₂,j₂) THEN they SHALL be computed in O(√T) time and O(√T) space

### Requirement 8: Polynomial Commitment Schemes

**User Story:** As a cryptographic engineer, I want to commit to polynomials in small space, so that proof generation doesn't require storing entire commitment keys.

#### Acceptance Criteria

8.1. WHEN using Dory commitment scheme with Twist and Shout THEN the system SHALL store commitment key of size 2√(KT) group elements

8.2. WHEN prover space is O(√T) for polynomial of size T THEN the system SHALL implement Dory prover with no slowdown compared to linear-space implementation

8.3. WHEN using Hyrax commitment scheme THEN the system SHALL implement prover in space O(√T) with no time overhead

8.4. WHEN space as low as O(log T) is desired THEN the system SHALL adapt techniques from [BHR+20] achieving O(T log T) prover time

8.5. WHEN generating commitment key on-the-fly THEN the system SHALL evaluate cryptographic PRG and apply hash-to-curve procedure requiring O(λ) field operations per group element

8.6. WHEN hash-to-curve bottleneck is square root computation in F THEN the system SHALL account for O(log |F|)=O(λ) field operations per element

8.7. WHEN using Hyrax with commitment key g=(g₁,...,g_{√n}) THEN commitment to polynomial p SHALL be vector h=(h₁,...,h_{√n}) where:
```
hᵢ = ⟨Mᵢ,g⟩
```
and Mᵢ is i-th column of √n × √n matrix M representing p

8.8. WHEN computing Hyrax commitment in small space THEN the system SHALL:
- Stream entries of M in column-major order
- Store O(√n) space for commitment key g
- Apply Pippenger's algorithm independently to each column

8.9. WHEN producing Hyrax evaluation proof (simplest variation) for p(r) THEN prover SHALL send vector k∈F^√n claimed to equal M·r₂ where:
```
r₁ = ⊗_{i=1}^{log n/2} (1-rᵢ,rᵢ)
r₂ = ⊗_{i=log n/2+1}^{log n} (1-rᵢ,rᵢ)
```

8.10. WHEN verifier checks Hyrax evaluation proof THEN it SHALL:
- Compute c* = ⟨r₂,h⟩
- Confirm ⟨k,g⟩ = c*
- Verify p(r) = ⟨r₁,k⟩

8.11. WHEN producing Hyrax evaluation proof (second variation using Bulletproofs) THEN prover SHALL prove knowledge of w₁ such that:
- w₁ = M·r₂
- y = ⟨r₁,w₁⟩ where y is claimed evaluation p(r)

8.12. WHEN executing Bulletproofs protocol in round i THEN prover SHALL maintain:
- Witness vectors wᵢ and uᵢ of size √n/2^(i-1)
- Generator vector Gᵢ of group elements of size √n/2^(i-1)
- Property yᵢ = ⟨uᵢ,wᵢ⟩

8.13. WHEN computing next round in Bulletproofs THEN for verifier challenge αᵢ∈F:
```
wᵢ₊₁ = αᵢ·wᵢ,L + αᵢ⁻¹·wᵢ,R
uᵢ₊₁ = αᵢ⁻¹·uᵢ,L + αᵢ·uᵢ,R
Gᵢ₊₁ = αᵢ⁻¹·Gᵢ,L + αᵢ·Gᵢ,R
```

8.14. WHEN computing cross-terms in Bulletproofs round i THEN prover SHALL send:
```
yᵢ,L = ⟨uᵢ,L,wᵢ,R⟩
yᵢ,R = ⟨uᵢ,R,wᵢ,L⟩
⟨wᵢ,L,Gᵢ,R⟩
⟨wᵢ,R,Gᵢ,L⟩
```

8.15. WHEN using Dory commitment scheme THEN commitment SHALL be computed as:
```
∏ᵢ₌₁^√n e(hᵢ,qᵢ)
```
where e is bilinear map, h is Hyrax commitment, and q₁,...,q_{√n} are AFGHO commitment key elements

8.16. WHEN using hash-based PCS (Ligero, Brakedown, Binius) THEN the system SHALL:
- Arrange n evaluations into √n × √n matrix M
- Apply error-correcting code encoding to each row
- Merkle-hash encoded rows
- Achieve O(√n) space with single pass in row-major order

8.17. WHEN producing evaluation proof for hash-based PCS THEN prover SHALL:
- Compute linear combination of rows with coefficients from r
- Open O(λ) randomly chosen columns
- Both operations in O(√n) space with single pass



### Requirement 9: Space-Time Trade-offs

**User Story:** As a system architect, I want configurable space-time trade-offs, so that prover can be optimized for different deployment scenarios.

#### Acceptance Criteria

9.1. WHEN target space is O(K+log T) THEN the system SHALL achieve this for appropriate polynomial commitment schemes

9.2. WHEN target space is O(K+T^(1/2)) THEN the system SHALL provide simpler and faster prover implementation

9.3. WHEN enough sum-check rounds have passed that space requirement halves below target THEN the system SHALL switch from small-space to linear-time prover algorithm

9.4. WHEN K≥2²⁵ and T≤2³⁵ THEN the system SHALL recognize O(K+log T) and O(K+T^(1/2)) are equivalent up to constant factors

9.5. WHEN storing T^(1/2) field elements for T=2⁴⁰ THEN the system SHALL require only dozens of MBs versus 10+ GBs for recursion-based approaches

9.6. WHEN using Dory with Twist and Shout THEN commitment key SHALL consist of 2√(KT) group elements

9.7. WHEN using dimension parameter d in Twist THEN commitment key size SHALL be reduced to 2√(K^(1/d)·T) group elements

9.8. WHEN K=2²⁵ and T=2³⁵ THEN storing 2√(KT) field elements SHALL cost approximately 100 GBs

9.9. WHEN Dory commitment key size is reduced by factor of 10+ THEN space SHALL be brought down to 10 GBs or less

9.10. WHEN using small-value optimization for first c rounds THEN space reduction SHALL be 2^c-fold

### Requirement 10: Integration with Jolt zkVM

**User Story:** As a Jolt developer, I want to integrate small-space proving into Jolt, so that the complete zkVM operates with reduced memory footprint.

#### Acceptance Criteria

10.1. WHEN Jolt prover uses Twist and Shout with K=2²⁵ and T=2³⁵ THEN the system SHALL perform approximately 900T field multiplications in linear-space mode

10.2. WHEN small-space implementation is used THEN the system SHALL increase field multiplications by approximately 12T log T ≈ 400T operations

10.3. WHEN 12T log T << 900T for realistic T values THEN the system SHALL demonstrate that quasilinear time with small constant is faster than linear time with large constant

10.4. WHEN Spartan prover performs 250T field operations in linear space THEN small-space SHALL add at most 40T additional operations

10.5. WHEN Shout for instruction execution performs 40T operations in linear space THEN small-space SHALL add at most 2T log T operations

10.6. WHEN Twist for registers performs 35T operations in linear space THEN small-space SHALL add at most 4T log T operations

10.7. WHEN Twist for RAM performs up to 150T operations in linear space THEN small-space SHALL add at most 4T log T operations

10.8. WHEN commitment costs are approximately 350T field operations THEN the system SHALL maintain this cost in small-space mode with O(√(KT)) space

10.9. WHEN Jolt commits to values per cycle THEN it SHALL commit to less than 30 non-zero values per cycle (down from 61 with Spice and Lasso)

10.10. WHEN committed values are analyzed THEN at least 8 SHALL equal 1, and remaining 22 or fewer SHALL be in {0,1,...,2³²-1} (mostly in {0,1,...,2¹⁶-1})

10.11. WHEN estimating commitment costs THEN crude estimate SHALL be at most 50 group operations per RISC-V cycle, translating to roughly 350 field operations per cycle

10.12. WHEN computing evaluation proofs with Dory THEN cost SHALL be at most 30T field operations plus O(1) multi-pairings of size O(√(KT))

10.13. WHEN witness generation is repeated up to log K + (1/2)·log T ≈ 40 times with 16 threads THEN parallel runtime SHALL increase by factor less than 3

10.14. WHEN total witness generation time is under 5% of prover time THEN repeated generation SHALL add less than 15% to total time

10.15. WHEN Jolt prover slowdown is measured for T≥2²⁰ THEN it SHALL be well under 2× compared to linear-space implementation

### Requirement 11: Correctness Properties

**User Story:** As a verification engineer, I want formal correctness guarantees, so that small-space proving produces identical results to linear-space proving.

#### Acceptance Criteria

11.1. WHEN Algorithm 1 (Small Space Sum-Check) is executed THEN it SHALL produce identical prover messages to the standard linear-time algorithm

11.2. WHEN witness is regenerated from checkpoints THEN it SHALL be identical to originally generated witness

11.3. WHEN prefix-suffix inner product protocol is used THEN it SHALL compute the same sum as standard sum-check

11.4. WHEN small-value sum-check optimization is applied THEN it SHALL produce identical results to standard algorithm for all field values

11.5. WHEN switching between small-space and linear-space algorithms mid-protocol THEN the transition SHALL be seamless with no correctness impact

11.6. WHEN Claim 3.2 is applied THEN for i∈{1,...,n-1} and m∈{0,...,2^(n-(i-1))-1}, m-th entry of A_{k,i} SHALL equal:
```
Σ_{j∈{0,...,2^(i-1)-1}} ẽq(r₁,...,rᵢ₋₁,tobits(j))·Aₖ[2^(i-1)·m + j]
```

11.7. WHEN Fact 2.1 is applied THEN for any multilinear polynomial ũ and any c∈F, x∈F^(n-1):
```
ũ(c,x) = (1-c)·ũ(0,x) + c·ũ(1,x)
```

11.8. WHEN sum-check soundness is analyzed THEN error SHALL be at most ℓ·n/|F|

### Requirement 12: Performance Bounds

**User Story:** As a performance analyst, I want concrete performance bounds, so that deployment decisions can be made with confidence.

#### Acceptance Criteria

12.1. WHEN prover slowdown factor is measured THEN it SHALL be well under 2× for realistic T values (T≥2²⁰)

12.2. WHEN sparse sums are processed in early rounds THEN the system SHALL incur no time overhead for small-space operation

12.3. WHEN dense sums are processed in final log T rounds THEN the system SHALL incur time overhead only in these rounds

12.4. WHEN witness generation is repeated up to 40 times with 16 threads THEN parallel runtime SHALL increase by less than factor of 3

12.5. WHEN total witness generation time is under 5% of prover time THEN repeated generation SHALL add less than 15% to total time

12.6. WHEN using small-value optimization for first 8 rounds THEN the system SHALL achieve 2⁸=256-fold space reduction with minimal time overhead

12.7. WHEN linear-space Jolt prover runs THEN it SHALL perform between 500T and 900T field operations total

12.8. WHEN small-space Jolt prover runs THEN it SHALL add approximately 12T log T ≈ 400T field operations for T=2³⁵

12.9. WHEN 256-bit field multiplication is performed THEN it SHALL require less than 80 CPU cycles

12.10. WHEN prover requires 900 field operations per cycle THEN slowdown relative to native execution SHALL be approximately 900·80 = 72,000

12.11. WHEN Theorem 3.1 applies THEN linear-time sum-check prover SHALL take time and space O(2^(n-i)) in round i

12.12. WHEN Theorem 3.3 applies THEN Algorithm 1 SHALL have time complexity O(ℓ²n·2ⁿ) and space complexity O(n+ℓ²)

12.13. WHEN Theorem 7.1 applies THEN for RISC-V program executed in T cycles using K words of RAM, honest prover SHALL use S=O(K+log T) space and run in O(T log T) time plus polynomial evaluation proof time

### Requirement 13: Security Properties

**User Story:** As a security engineer, I want to maintain security guarantees, so that small-space proving doesn't compromise soundness.

#### Acceptance Criteria

13.1. WHEN sum-check soundness error is ℓ·n/|F| for standard algorithm THEN small-space SHALL maintain identical soundness

13.2. WHEN Fiat-Shamir transformation is applied THEN the system SHALL avoid recursion-related security concerns

13.3. WHEN algebraic hash functions are avoided THEN the system SHALL rely only on standard cryptographic assumptions

13.4. WHEN commitment scheme security is based on discrete logarithm THEN small-space SHALL not weaken this assumption

13.5. WHEN random oracle model security holds for non-recursive SNARK THEN small-space SHALL preserve this property

13.6. WHEN Definition 2.2 (Succinct Argument of Knowledge) applies THEN the system SHALL satisfy:
- Completeness: Pr{⟨P,V⟩(pp,x;w) = 1} = 1 for all (x,w)∈R
- Knowledge-Soundness: For any PPT P₁,P₂ there exists PPT Ext such that Pr{(x,w)∉R ∧ ⟨P₂,V⟩(pp,x;st)=1} = negl(λ)

13.7. WHEN Definition 2.5 (PCS Completeness) applies THEN for any polynomial f(X) with at most D≤N monomials and any x∈F^n:
```
Pr{b=1 : pp←setup(1^λ,N), (C,c̃)←commit(pp,f(X),D), y←f(x), b←eval(pp,C,D,x,y;f(X))} = 1
```

13.8. WHEN Definition 2.6 (PCS Binding) applies THEN for every PPT adversary A:
```
Pr{open(pp,f₀,D,C,c̃₀)=1 ∧ open(pp,f₁,D,C,c̃₁)=1 ∧ f₀≠f₁ : pp←setup(1^λ,N), (C,f₀,f₁,c̃₀,c̃₁,D)←A(pp)} = negl(λ)
```

13.9. WHEN Definition 2.7 (PCS Knowledge Soundness) applies THEN eval SHALL be AoK for relation:
```
R_eval = {((pp,C,x←_R F^n,y∈F);(f(X),c̃)) : (open(pp,f,D,C,c̃)=1) ∧ y=f(x)}
```



### Requirement 14: Grand Product Check in Small Space (Algorithm 3)

**User Story:** As a protocol implementer, I want to verify grand products in small space, so that Lasso and Spice can operate efficiently.

#### Mathematical Foundation (Lemma D.1)

P = ∏_{x∈{0,1}^n} v(x) if and only if there exists multilinear polynomial f in n+1 variables such that:
1. f(0,1,...,1) = P
2. f(x,0) = v(x) for all x∈{0,1}^n
3. f(x,1) = f(0,x)·f(1,x) for all x∈{0,1}^n

#### Acceptance Criteria

14.1. WHEN verifying grand product relation THEN the system SHALL check:
```
R = {(P∈F, V∈F^m) | P = ∏_{i∈{1,...,m}} vᵢ}
```

14.2. WHEN applying Lemma D.1 THEN verifier SHALL directly check f(0,1,...,1) = P

14.3. WHEN applying Lemma D.1 THEN verifier SHALL check f(u,0) = v(u) for uniformly random u∈F^n

14.4. WHEN applying Lemma D.1 THEN verifier SHALL apply sum-check to verify for random u∈F^n:
```
0 = Σ_{x∈{0,1}^n} ẽq(u,x)·(f(x,1) - f(0,x)·f(1,x))
```

14.5. WHEN defining g₀(X)=ẽq(u,X), g₁(X)=f(X,1), g₂(X)=f(0,X), g₃(X)=f(1,X) THEN sum-check SHALL be applied to:
```
Σ_{x∈{0,1}^n} g₀(x)·(g₁(x) - g₂(x)·g₃(x))
```

14.6. WHEN polynomial f represents product computation THEN it SHALL correspond to depth-n binary tree circuit of product gates

14.7. WHEN layer j of circuit is considered THEN it SHALL contain 2^(n-j) nodes for j∈{0,...,n}

14.8. WHEN evaluations f(x,0,1^j) for x∈{0,1}^(n-j) are considered THEN they SHALL correspond to values of nodes in layer j

14.9. WHEN computing g₁(x'), g₂(x'), g₃(x') for x'=(x,0,1^(j-1)) THEN the relation SHALL hold:
```
g₁(x') = g₂(x')·g₃(x')
```

14.10. WHEN implementing Algorithm 3 THEN the system SHALL use stack st to store intermediate values with at most n+1 elements

14.11. WHEN implementing Algorithm 3 Step 5 THEN g_evals[j][k][s] SHALL accumulate terms for gₖ(r₁,...,rᵢ₋₁,αₛ,tobits(m)) based on number of leading ones in m

14.12. WHEN processing string x at Step 6 THEN algorithm SHALL iterate while loop exactly for number of trailing ones in x

14.13. WHEN Lemma D.2 applies and 1∈J_x THEN stack st SHALL contain:
- Values g₂(x^(j)) for all (j+1)∈J_x in decreasing order of j
- Followed by g₃(x^(0))

14.14. WHEN Lemma D.2 applies and 1∉J_x THEN stack st SHALL contain:
- Values g₂(x^(j)) for all (j+1)∈J_x in decreasing order of j

14.15. WHEN Claim D.3 applies and least significant bit of x^(j) is 0 THEN:
```
g₁(x^(j)) = g₂(x^(j+1))
```

14.16. WHEN Claim D.3 applies and least significant bit of x^(j) is 1 THEN:
```
g₁(x^(j)) = g₃(x^(j+1))
```

14.17. WHEN Algorithm 3 Step 15 executes THEN it SHALL compute:
```
g₁(x^(j)) = g₂(x^(j))·g₃(x^(j))
```

14.18. WHEN Algorithm 3 Step 17 executes THEN t SHALL determine appropriate index in g_evals based on:
```
t = min(j, n-i)
```

14.19. WHEN Algorithm 3 Step 23 condition is met THEN 2^i terms SHALL have been added to g_evals[t][k][s]

14.20. WHEN Algorithm 3 Step 24 executes THEN it SHALL add to accumulator[s]:
```
g_evals[t][0][s]·(g_evals[t][1][s] - g_evals[t][2][s]·g_evals[t][3][s])
```

14.21. WHEN Algorithm 3 handles special case 1^n THEN it SHALL set:
- g₁(1^n) = 0
- g₃(1^n) = 0  
- g₂(1^n) = g₁(0,1^(n-1))

14.22. WHEN Theorem D.4 applies THEN Algorithm 3 SHALL operate in O(n) space and O(n·2^n) time

### Requirement 15: Lasso for Indexed Lookup Arguments

**User Story:** As a lookup argument implementer, I want to prove correct lookups into decomposable tables in small space, so that primitive instruction execution is verified efficiently.

#### Mathematical Foundation

Definition E.1 (Indexed Lookup Argument): Lookup argument for table T∈F^N is SNARK for relation:
```
{(pp,C_ã,C_b̃) | ∃a,b∈F^m such that aᵢ=T[bᵢ] ∀i∈[0,n-1] and open(pp,C_ã,a)=1, open(pp,C_b̃,b)=1}
```

Definition E.2 (MLE-Structured): Table T∈F^N is MLE-structured if for any r∈F^(log N), T̃(r) can be evaluated using O(log N) field operations.

Definition E.3 (Decomposable Tables): Table T∈F^N is c-decomposable if there exists constant k∈ℕ, α≤k·c tables T₁,...,T_α∈F^(N^(1/c)), and α-variate polynomial G such that for all r∈F^(log N):
```
T̃(r) = G(T̃₁(r₁),...,T̃ₖ(r₁), T̃_{k+1}(r₂),...,T̃_{2k}(r₂),...,T̃_α(r_c))
```

#### Acceptance Criteria

15.1. WHEN table T is c-decomposable THEN lookup aᵢ=T[bᵢ] SHALL be decomposed as:
```
aᵢ = T[bᵢ] = G(T₁[b_{1,i}],...,Tₖ[b_{1,i}], T_{k+1}[b_{2,i}],...,T_{2k}[b_{2,i}],...,T_α[b_{c,i}])
```

15.2. WHEN defining a_j∈F^m such that a_{j,i}=T_j[b_{⌊j/k⌋,i}] THEN for all i∈[0,N-1]:
```
aᵢ = G(a_{1,i},...,a_{α,i})
```

15.3. WHEN Lasso proof is constructed THEN it SHALL consist of:
- Sum-check protocol proving aᵢ=G(a_{1,i},...,a_{α,i})
- Indexed lookup arguments for sub-tables proving a_{j,i}=T_j[b_{⌊j/k⌋,i}]

15.4. WHEN sum-check in Lasso is applied THEN it SHALL reduce relation to opening MLEs of a and a_j for all j∈[1,α] at random point

15.5. WHEN polynomial G is sum of O(1) products of variables THEN sum-check SHALL be adapted to operate in O(m) space and O(m·log m) time

15.6. WHEN lookups into sub-tables are proved THEN read-only memory checking argument from Spice SHALL be used

15.7. WHEN Theorem E.4 applies THEN for c-decomposable table T with witness generation algorithm computing vectors in O(1) space and time per element, honest prover SHALL operate in O(log m + N^(1/c)) space and O(m·log m + N^(1/c)) time

15.8. WHEN Lasso prover commits to data THEN it SHALL commit to 3cm + c·N^(1/c) elements

15.9. WHEN Lasso verifier operates THEN it SHALL perform O(log m) hashes and field operations plus evaluation proofs of few log m-variate multilinear polynomials

### Requirement 16: Spice for Read/Write Memory Checking

**User Story:** As a memory consistency verifier, I want to prove correct read/write operations in small space, so that register and RAM operations are verified.

#### Mathematical Foundation (Algorithm 2)

Memory M of size N with T reads and writes. Each entry is tuple (index, value, timestamp).

#### Acceptance Criteria

16.1. WHEN memory M has size N and T operations are performed THEN the system SHALL construct sets:
- Reads: tuples of read operations
- Writes: tuples of write operations  
- Memory_Init: initial memory state
- Memory_Fin: final memory state

16.2. WHEN Algorithm 2 initializes memory THEN for i∈[0,N-1]:
```
Mem[i].0 ← i
Mem[i].1 ← M[i]
Mem[i].2 ← 0
```

16.3. WHEN Algorithm 2 processes operation j THEN it SHALL:
- Add Mem[address[j]] to Reads
- Update Mem[address[j]].1 ← write_val[j]
- Update Mem[address[j]].2 ← universal_timestamp
- Add updated Mem[address[j]] to Writes
- Increment universal_timestamp

16.4. WHEN reads and writes are consistent THEN the following SHALL hold:
1. Reads ∪ Memory_Fin = Writes ∪ Memory_Init
2. For all j∈[0,T-1]: reads_ts[j] ≤ idx[j]

16.5. WHEN verifier samples γ,τ∈F uniformly at random THEN gpr_reads_vector SHALL be vector of length T+N with elements:
```
(a + γ·v + γ²·t - τ) for tuple (a,v,t)∈Reads ∪ Memory_Fin
```

16.6. WHEN gpr_writes_vector is defined THEN it SHALL be vector of length T+N with elements:
```
(a + γ·v + γ²·t - τ) for tuple (a,v,t)∈Writes ∪ Memory_Init
```

16.7. WHEN products are computed THEN:
```
prod_reads = ∏_{j∈[0,T+N-1]} gpr_reads_vector[j]
prod_writes = ∏_{j∈[0,T+N-1]} gpr_writes_vector[j]
```

16.8. WHEN Schwartz-Zippel argument applies THEN with high probability over γ,τ:
```
Reads ∪ Memory_Fin = Writes ∪ Memory_Init ⟺ prod_reads = prod_writes
```

16.9. WHEN grand-product check is applied THEN prover and verifier SHALL use Algorithm 3 to prove prod_reads and prod_writes are computed correctly

16.10. WHEN MLEs are evaluated THEN evaluations of MLEs for gpr_reads_vector and gpr_writes_vector SHALL be obtained from MLEs of:
- reads_index, writes_index
- reads_val, writes_val
- reads_ts, writes_ts
- idx

16.11. WHEN witness vectors are committed THEN prover SHALL commit to MLEs of:
- address (equals reads_index and writes_index)
- reads_val
- writes_val
- reads_ts

16.12. WHEN idx MLE is evaluated THEN it SHALL be computed in O(log T) time using:
```
ĩdx(x₀,...,x_{log T-1}) = Σ_{j∈[0,log T-1]} 2^j·x_j
```

16.13. WHEN writes_ts is related to idx THEN for all j∈[0,T-1]:
```
writes_ts[j] = idx[j] + 1
```



### Requirement 17: Implementation Constraints

**User Story:** As a software engineer, I want clear implementation guidelines, so that the system can be built correctly and efficiently.

#### Acceptance Criteria

17.1. WHEN implementing Algorithm 1 THEN the system SHALL use nested loops with outer loop over m∈{0,...,2^(n-i)-1} and inner loop over j∈{0,...,2^(i-1)-1}

17.2. WHEN storing intermediate values THEN the system SHALL use arrays of size O(ℓ²) for witness_eval and O(ℓ+1) for accumulator

17.3. WHEN querying oracles THEN the system SHALL compute indices as:
```
u_even = 2^i·2m + j
u_odd = 2^i·(2m+1) + j
```

17.4. WHEN computing multilinear extensions THEN the system SHALL use Fact 2.1:
```
ũ(c,x) = (1-c)·ũ(0,x) + c·ũ(1,x)
```

17.5. WHEN implementing checkpointing THEN the system SHALL store VM state snapshots at intervals of T/M for M threads

17.6. WHEN dimension parameter d is chosen THEN it SHALL be set as small as possible subject to:
- Commitment key size constraints (for curve-based schemes)
- Commitment time constraints (for hash-based schemes)

17.7. WHEN field F has size at least 2^λ for security parameter λ THEN the system SHALL ensure all operations are performed in this field

17.8. WHEN implementing linear-time sum-check update (Equation 4) THEN for round i-1:
```
Aₖ[m] = (1-rᵢ₋₁)·Aₖ[2m] + rᵢ₋₁·Aₖ[2m+1]
```
for m∈{0,1,...,2^(n-(i-1))} and k∈{1,...,ℓ}

17.9. WHEN implementing small-value optimization THEN the system SHALL:
- Use array C of size 2^n initially
- Compute C[j] = A₁[j]·A₂[j] = g₁(tobits(j))·g₂(tobits(j))
- Maintain array E storing {ẽq(rᵢ₋₁,y₁)·ẽq(rᵢ₋₁,y₂)}_{y₁,y₂∈{0,1}ⁱ}

17.10. WHEN implementing Hyrax commitment THEN the system SHALL:
- Arrange polynomial evaluations in √n × √n matrix M
- Commit to each column independently
- Use Pippenger's algorithm for MSMs

17.11. WHEN implementing Bulletproofs protocol THEN the system SHALL:
- Use interleaved partitioning (left half = odd indices, right half = even indices)
- Stream matrix M in column-major order
- Generate commitment key elements on-the-fly if needed

17.12. WHEN implementing hash-based PCS THEN the system SHALL:
- Arrange evaluations in √n × √n matrix
- Encode each row independently
- Merkle-hash rows (or columns)
- Stream in row-major order for encoding

17.13. WHEN implementing Twist and Shout THEN the system SHALL:
- Set dimension parameter d based on memory size K
- Use d=1 for small memories (32 registers)
- Use d=1-4 for curve-based commitments
- Use d=1-16 for hash-based commitments over binary fields

17.14. WHEN implementing pcnext-evaluation sum-check THEN the system SHALL:
- Use prefix-suffix inner product protocol
- Make C passes over pc evaluations
- Achieve O(T) runtime and O(C·T^(1/C)) space

17.15. WHEN implementing M̃-evaluation sum-check THEN the system SHALL:
- Use prefix-suffix inner product protocol
- Make C passes over write operations
- Achieve O(T) runtime and O(C·T^(1/C)) space

17.16. WHEN implementing grand product check THEN the system SHALL:
- Use depth-first traversal of binary tree
- Maintain stack of at most n+1 elements
- Process strings in lexicographic order
- Partition by number of leading ones

17.17. WHEN generating ẽq evaluations in lexicographic order THEN the system SHALL use techniques from [CFFZE24] or [Rot24] achieving O(T) time and O(log T) space

17.18. WHEN computing s̃hift evaluations THEN the system SHALL:
- Enumerate h(r,j) evaluations in O(T) time and O(log T) space
- Enumerate g(r,j) evaluations via depth-first tree traversal
- Perform O(T) total field multiplications

### Requirement 18: Testing and Validation

**User Story:** As a quality assurance engineer, I want comprehensive testing requirements, so that correctness can be verified.

#### Acceptance Criteria

18.1. WHEN comparing small-space and linear-space provers THEN they SHALL produce bit-identical proofs for same inputs

18.2. WHEN testing with T∈{2²⁰,2²⁵,2³⁰,2³⁵} THEN the system SHALL demonstrate space reduction and bounded time overhead

18.3. WHEN measuring memory usage THEN it SHALL be verified to be O(K+T^(1/2)) or O(K+log T) as configured

18.4. WHEN testing witness regeneration THEN checkpointed regeneration SHALL produce identical witnesses to original generation

18.5. WHEN testing prefix-suffix protocol THEN it SHALL correctly compute inner products for all valid prefix-suffix structured polynomials

18.6. WHEN testing small-value optimization THEN it SHALL correctly handle values in B={0,1,...,2³²-1} and switch to standard algorithm at appropriate round

18.7. WHEN testing Twist and Shout THEN they SHALL correctly verify all memory operations with small-space provers

18.8. WHEN testing Spartan THEN it SHALL correctly prove R1CS satisfaction with block-diagonal matrices in small space

18.9. WHEN testing Algorithm 1 THEN it SHALL:
- Produce correct fᵢ(αₛ) for all rounds i and evaluation points αₛ
- Maintain space O(n+ℓ²) throughout execution
- Complete in time O(ℓ²n·2ⁿ)

18.10. WHEN testing Algorithm 3 (grand product) THEN it SHALL:
- Correctly compute all gₖ evaluations
- Maintain stack size ≤ n+1
- Produce correct accumulator values

18.11. WHEN testing Hyrax commitment THEN it SHALL:
- Produce correct commitments in O(√n) space
- Generate correct evaluation proofs
- Verify correctly with verifier

18.12. WHEN testing Dory commitment THEN it SHALL:
- Produce correct AFGHO commitments to Hyrax commitments
- Generate correct evaluation proofs in O(√n) space
- Complete multi-pairings correctly

18.13. WHEN testing hash-based PCS THEN it SHALL:
- Encode rows correctly
- Produce valid Merkle proofs
- Verify correctly with O(√n) space

18.14. WHEN testing Lasso THEN it SHALL:
- Correctly decompose lookups into sub-table lookups
- Verify all sub-table lookups correctly
- Produce correct final lookup results

18.15. WHEN testing Spice THEN it SHALL:
- Correctly track memory timestamps
- Verify read/write consistency
- Produce correct grand product values

18.16. WHEN testing with different field sizes THEN the system SHALL:
- Work correctly over prime fields of size ≥2^λ
- Work correctly over binary fields GF(2^128)
- Maintain security parameter λ bits of security

18.17. WHEN testing soundness THEN the system SHALL:
- Verify sum-check soundness error ≤ ℓ·n/|F|
- Verify Schwartz-Zippel argument holds with high probability
- Verify all cryptographic assumptions hold

18.18. WHEN testing completeness THEN the system SHALL:
- Accept all valid proofs with probability 1
- Produce valid proofs for all valid witnesses
- Maintain consistency across all protocol components

18.19. WHEN performance testing THEN the system SHALL measure:
- Total field operations per cycle
- Memory usage throughout execution
- Witness generation time
- Commitment time
- Evaluation proof time
- Total prover time

18.20. WHEN comparing to linear-space implementation THEN metrics SHALL show:
- Space reduction to O(K+T^(1/2)) or O(K+log T)
- Time overhead < 2× for T≥2²⁰
- Correct functionality maintained

### Requirement 19: Concrete Performance Targets

**User Story:** As a deployment engineer, I want concrete performance targets, so that I can plan resource allocation.

#### Acceptance Criteria

19.1. WHEN K=2²⁵ and T=2³⁵ THEN the system SHALL:
- Use approximately 100 GBs for commitment key (or 10 GBs with optimizations)
- Perform approximately 900T + 400T = 1300T field operations
- Complete in time < 2× linear-space implementation

19.2. WHEN using Spartan in small space THEN it SHALL:
- Perform approximately 250T + 40T = 290T field operations
- Use O(log T) space after switching from small-value optimization

19.3. WHEN using Shout for instruction execution THEN it SHALL:
- Perform approximately 40T + 2T log T ≈ 110T field operations for T=2³⁵
- Use O(K^(1/C) + T^(1/C)) space

19.4. WHEN using Shout for bytecode lookups THEN it SHALL:
- Perform approximately 5T + 2T log T field operations
- Use O(log T) space

19.5. WHEN using Twist for registers THEN it SHALL:
- Perform approximately 35T + 4T log T field operations
- Use O(log T) space

19.6. WHEN using Twist for RAM THEN it SHALL:
- Perform approximately 150T + 4T log T field operations worst-case
- Use O(K + T^(1/2)) space
- Perform O(i·T) operations for i-local accesses

19.7. WHEN computing commitments THEN the system SHALL:
- Commit to < 30 non-zero values per cycle
- Perform ≤ 50 group operations per cycle
- Translate to approximately 350 field operations per cycle

19.8. WHEN computing evaluation proofs with Dory THEN the system SHALL:
- Perform ≤ 30T field operations
- Perform O(1) multi-pairings of size O(√(KT))
- Complete in time comparable to linear-space implementation

19.9. WHEN witness generation is repeated THEN the system SHALL:
- Repeat up to log K + (1/2)·log T ≈ 40 times
- Use 16 threads for parallel regeneration
- Increase total time by < 15%

19.10. WHEN total prover time is measured THEN it SHALL be:
- Linear-space: 500T to 900T field operations
- Small-space: 500T to 900T + 12T log T field operations
- Slowdown: < 2× for T≥2²⁰

## Summary

This requirements document provides COMPLETE and EXHAUSTIVE mathematical specifications for implementing a small-space zkVM prover based on the "Proving CPU Executions in Small Space" paper. Every mathematical formulation, equation, algorithm, and technical detail has been captured without omission or simplification.

The requirements cover:
- Complete mathematical preliminaries and notation (Requirement 0)
- Small-space sum-check protocol with all formulas (Requirements 1-2)
- Streaming witness generation (Requirement 3)
- Spartan for uniform R1CS with complete equations (Requirement 4)
- Shout and Twist protocols with all mathematical details (Requirements 5-6)
- Prefix-suffix inner product protocol (Requirement 7)
- Polynomial commitment schemes (Requirement 8)
- Space-time tradeoffs (Requirement 9)
- Jolt integration with concrete performance estimates (Requirement 10)
- Correctness, performance, and security properties (Requirements 11-13)
- Grand product check with complete algorithm (Requirement 14)
- Lasso and Spice with full mathematical foundations (Requirements 15-16)
- Implementation constraints and testing (Requirements 17-18)
- Concrete performance targets (Requirement 19)

All 19 requirements with 400+ acceptance criteria provide the complete specification needed for implementation.

