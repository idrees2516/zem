# Design Document: Linear-Time Permutation Check

## Overview

This document provides the technical design for implementing the Linear-Time Permutation Check protocol suite, including BiPerm, MulPerm, and their extensions to lookup arguments. The implementation will provide permutation and lookup arguments with polylogarithmic soundness error, logarithmic verification cost, and linear or near-linear prover time.

The design follows a layered architecture:
1. **Foundation Layer**: Field arithmetic, polynomial operations, basic cryptographic primitives
2. **Protocol Layer**: Sumcheck, permutation checks, lookup arguments
3. **Integration Layer**: PCS compilation, SNARK system integration
4. **Application Layer**: HyperPlonk, Spartan, R1CS-GKR implementations

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  HyperPlonk  │  │   Spartan    │  │  R1CS-GKR    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                   Integration Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ PCS Compiler │  │  Fiat-Shamir │  │   Batching   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                    Protocol Layer                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   BiPerm     │  │   MulPerm    │  │  MulLookup   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Sumcheck   │  │  Bucketing   │  │ Prover-Prov  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                   Foundation Layer                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Field Arith  │  │  Polynomials │  │   Eq Poly    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │     MLE      │  │     FFT      │  │  Boolean HC  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

```
Permutation Check Request
         │
         ▼
┌─────────────────────┐
│ Preprocess σ or ρ   │ ← Compute MLEs, indicator functions
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ Choose Protocol     │ ← BiPerm (sparse PCS) or MulPerm (any PCS)
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ Run Sumcheck(s)     │ ← 1 sumcheck (BiPerm) or 2 sumchecks (MulPerm)
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ PCS Compilation     │ ← Commit to oracles, open at query points
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ Fiat-Shamir         │ ← Make non-interactive
└─────────────────────┘
         │
         ▼
    Proof Output
```


## Components and Interfaces

### Foundation Layer Components

#### 1. Field Arithmetic Module

```rust
trait Field: Clone + Copy + Debug {
    fn zero() -> Self;
    fn one() -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn inv(&self) -> Option<Self>;
    fn neg(&self) -> Self;
    fn pow(&self, exp: u64) -> Self;
    fn random<R: Rng>(rng: &mut R) -> Self;
    fn from_u64(val: u64) -> Self;
    fn characteristic() -> BigUint;
}

// Concrete implementations
struct PrimeField<const P: u64>;
struct BinaryField<const N: usize>;
struct ExtensionField<F: Field, const DEG: usize>;
```

**Design Rationale**: Abstract field interface allows protocol to work with any finite field. Implementations for prime fields (most common), binary fields (efficient for certain operations), and extension fields (for larger security parameters).

#### 2. Polynomial Module

```rust
struct MultilinearPolynomial<F: Field> {
    num_vars: usize,
    evaluations: Vec<F>,  // Evaluations over B^μ
}

impl<F: Field> MultilinearPolynomial<F> {
    // Evaluate at point in F^μ
    fn evaluate(&self, point: &[F]) -> F;
    
    // Compute MLE from boolean evaluations
    fn from_evaluations(evals: Vec<F>) -> Self;
    
    // Partial evaluation: fix first k variables
    fn partial_eval(&self, prefix: &[F]) -> Self;
    
    // Add two MLEs
    fn add(&self, other: &Self) -> Self;
    
    // Multiply two MLEs (increases degree)
    fn mul(&self, other: &Self) -> Self;
}

struct UnivariatePolynomial<F: Field> {
    coefficients: Vec<F>,
}

impl<F: Field> UnivariatePolynomial<F> {
    fn degree(&self) -> usize;
    fn evaluate(&self, point: F) -> F;
    fn from_evaluations(points: &[(F, F)]) -> Self;  // Lagrange interpolation
}
```

**Design Rationale**: Multilinear polynomials are the core data structure. Store as evaluation table over boolean hypercube for efficiency. Univariate polynomials used for sumcheck round messages.

#### 3. Equality Polynomial Module

```rust
struct EqualityPolynomial;

impl EqualityPolynomial {
    // Compute eq(x, y) = ∏ᵢ [xᵢyᵢ + (1-xᵢ)(1-yᵢ)]
    fn evaluate<F: Field>(x: &[F], y: &[F]) -> F;
    
    // Compute eq(y, α) for all y ∈ B^μ in O(2^μ) time
    fn evaluate_all_boolean<F: Field>(alpha: &[F]) -> Vec<F>;
    
    // Compute eq as multilinear polynomial
    fn as_mle<F: Field>(y: &[F]) -> MultilinearPolynomial<F>;
}
```

**Design Rationale**: Equality polynomial is fundamental primitive used throughout. Optimized implementation for evaluating over all boolean points is critical for BiPerm performance.

#### 4. Boolean Hypercube Module

```rust
struct BooleanHypercube {
    num_vars: usize,
}

impl BooleanHypercube {
    fn new(num_vars: usize) -> Self;
    
    // Iterator over all points in B^μ
    fn iter(&self) -> impl Iterator<Item = Vec<bool>>;
    
    // Convert boolean vector to field elements
    fn to_field<F: Field>(&self, point: &[bool]) -> Vec<F>;
    
    // Size of hypercube
    fn size(&self) -> usize {
        1 << self.num_vars
    }
}
```

**Design Rationale**: Utility module for working with boolean hypercube. Provides iteration and conversion utilities.


### Protocol Layer Components

#### 5. Sumcheck Protocol Module

```rust
struct SumcheckProver<F: Field> {
    num_vars: usize,
    virtual_polynomial: Box<dyn VirtualPolynomial<F>>,
}

trait VirtualPolynomial<F: Field> {
    // Evaluate polynomial at point
    fn evaluate(&self, point: &[F]) -> F;
    
    // Compute round polynomial uₖ(X) = ∑_{x∈B^{μ-k}} f(α, X, x)
    fn compute_round_polynomial(&mut self, challenges: &[F]) -> UnivariatePolynomial<F>;
    
    // Degree in each variable
    fn degree(&self) -> usize;
}

struct SumcheckProof<F: Field> {
    round_polynomials: Vec<UnivariatePolynomial<F>>,
    final_evaluation: F,
}

impl<F: Field> SumcheckProver<F> {
    fn prove(&mut self, claimed_sum: F) -> SumcheckProof<F>;
}

struct SumcheckVerifier<F: Field> {
    num_vars: usize,
    degree: usize,
}

impl<F: Field> SumcheckVerifier<F> {
    fn verify(
        &self,
        proof: &SumcheckProof<F>,
        claimed_sum: F,
        final_point: &[F],
    ) -> Result<F, VerificationError>;
}
```

**Design Rationale**: Generic sumcheck implementation that works with any virtual polynomial. Prover computes round polynomials, verifier checks consistency. Virtual polynomial trait allows different arithmetizations (BiPerm, MulPerm, etc.) to plug in.

#### 6. Permutation Representation Module

```rust
struct Permutation {
    size: usize,
    mapping: Vec<usize>,  // σ(i) = mapping[i]
}

impl Permutation {
    fn new(mapping: Vec<usize>) -> Result<Self, PermutationError>;
    fn inverse(&self) -> Self;
    fn compose(&self, other: &Self) -> Self;
    fn is_valid(&self) -> bool;
}

struct PermutationMLE<F: Field> {
    num_vars: usize,
    // σ̃ᵢ(X) for each bit i
    bit_mles: Vec<MultilinearPolynomial<F>>,
}

impl<F: Field> PermutationMLE<F> {
    // Compute MLEs of permutation bits
    fn from_permutation(perm: &Permutation) -> Self;
    
    // Interpolate into single polynomial σ̃[μ](I, X)
    fn interpolate(&self) -> MultilinearPolynomial<F>;
    
    // Evaluate σ̃(x) = (σ̃₁(x), ..., σ̃μ(x))
    fn evaluate_map(&self, x: &[F]) -> Vec<F>;
}

struct IndicatorFunction<F: Field> {
    permutation_mle: PermutationMLE<F>,
}

impl<F: Field> IndicatorFunction<F> {
    // Compute 1̃σ(x, y) = eq(σ̃(x), y)
    fn evaluate(&self, x: &[F], y: &[F]) -> F;
    
    // Arithmetize as product: different strategies for BiPerm vs MulPerm
    fn arithmetize(&self, strategy: ArithmetizationStrategy) -> Box<dyn VirtualPolynomial<F>>;
}

enum ArithmetizationStrategy {
    BiPerm,           // 2-way split
    MulPerm { ell: usize },  // ℓ-way split
    Naive,            // μ-way split (baseline)
}
```

**Design Rationale**: Separate representation of permutation (as mapping) from its multilinear extension. Indicator function encapsulates different arithmetization strategies, allowing easy switching between BiPerm and MulPerm.


#### 7. BiPerm Protocol Module

```rust
struct BiPermProver<F: Field> {
    num_vars: usize,
    f: MultilinearPolynomial<F>,
    g: MultilinearPolynomial<F>,
    sigma_L: MultilinearPolynomial<F>,  // 1̃σL(X, YL)
    sigma_R: MultilinearPolynomial<F>,  // 1̃σR(X, YR)
}

struct BiPermProof<F: Field> {
    sumcheck_proof: SumcheckProof<F>,
    f_opening: F,
    sigma_L_opening: F,
    sigma_R_opening: F,
}

impl<F: Field> BiPermProver<F> {
    fn new(
        f: MultilinearPolynomial<F>,
        g: MultilinearPolynomial<F>,
        perm: &Permutation,
    ) -> Self;
    
    // Precompute 1̃σL and 1̃σR
    fn preprocess(&mut self);
    
    // Compute evaluation tables of 1̃σL(·, αL) and 1̃σR(·, αR) in O(n) time
    fn compute_indicator_tables(&self, alpha: &[F]) -> (Vec<F>, Vec<F>);
    
    // Run degree-3 sumcheck
    fn prove(&mut self, alpha: &[F]) -> BiPermProof<F>;
}

struct BiPermVerifier<F: Field> {
    num_vars: usize,
}

impl<F: Field> BiPermVerifier<F> {
    fn verify(
        &self,
        proof: &BiPermProof<F>,
        g_commitment: &Commitment,
        alpha: &[F],
    ) -> Result<(), VerificationError>;
}
```

**Design Rationale**: BiPerm splits permutation into left and right halves. Preprocessing computes the two n^1.5-sized indicator functions. Prover computes evaluation tables in O(√n) time using equality polynomial optimization, then runs degree-3 sumcheck in O(n) time.

#### 8. MulPerm Protocol Module

```rust
struct MulPermProver<F: Field> {
    num_vars: usize,
    ell: usize,  // Group parameter, typically √μ
    f: MultilinearPolynomial<F>,
    g: MultilinearPolynomial<F>,
    sigma_interpolated: MultilinearPolynomial<F>,  // σ̃[μ](I, X)
}

struct MulPermProof<F: Field> {
    first_sumcheck: SumcheckProof<F>,
    partial_product_claims: Vec<F>,  // Pⱼ for j ∈ [ℓ]
    second_sumcheck: SumcheckProof<F>,
    sigma_openings: Vec<F>,  // σ̃[μ] at √log n points
}

impl<F: Field> MulPermProver<F> {
    fn new(
        f: MultilinearPolynomial<F>,
        g: MultilinearPolynomial<F>,
        perm: &Permutation,
    ) -> Self;
    
    // Choose optimal ℓ = √μ
    fn choose_ell(&self) -> usize {
        (self.num_vars as f64).sqrt().ceil() as usize
    }
    
    // Compute p̃(x') for all x' ∈ B^{μ+log ℓ} using bucketing
    fn compute_partial_products(&self, alpha: &[F]) -> Vec<F>;
    
    // First sumcheck: reduce to ℓ claims
    fn first_sumcheck(&mut self, alpha: &[F]) -> (SumcheckProof<F>, Vec<F>);
    
    // Second sumcheck: prove partial product evaluations
    fn second_sumcheck(
        &mut self,
        beta: &[F],
        t: &[F],
        claimed_sum: F,
    ) -> SumcheckProof<F>;
    
    fn prove(&mut self, alpha: &[F]) -> MulPermProof<F>;
}

struct MulPermVerifier<F: Field> {
    num_vars: usize,
    ell: usize,
}

impl<F: Field> MulPermVerifier<F> {
    fn verify(
        &self,
        proof: &MulPermProof<F>,
        g_commitment: &Commitment,
        alpha: &[F],
    ) -> Result<(), VerificationError>;
}
```

**Design Rationale**: MulPerm uses double-sumcheck structure. First sumcheck reduces to ℓ claims about partial products. Second sumcheck proves those claims using preprocessed σ̃[μ]. Bucketing algorithm is key optimization in both phases.


#### 9. Bucketing Algorithm Module

```rust
struct BucketingAlgorithm<F: Field> {
    num_vars: usize,
    ell: usize,
    round: usize,
}

impl<F: Field> BucketingAlgorithm<F> {
    // Compute number of distinct polynomial identities in round k
    fn num_identities(&self) -> usize {
        let k = self.round;
        let mu_over_ell = self.num_vars / self.ell;
        1 << (1 << k) * mu_over_ell
    }
    
    // Precompute all possible polynomial identities
    fn compute_identity_buckets(
        &self,
        sigma: &MultilinearPolynomial<F>,
        alpha: &[F],
        challenges: &[F],
    ) -> Vec<UnivariatePolynomial<F>>;
    
    // Group evaluation points by which identity they match
    fn partition_by_identity(
        &self,
        sigma: &MultilinearPolynomial<F>,
        challenges: &[F],
    ) -> HashMap<usize, Vec<Vec<F>>>;
    
    // Compute round polynomial using buckets
    fn compute_round_polynomial(
        &self,
        identities: &[UnivariatePolynomial<F>],
        partitions: &HashMap<usize, Vec<Vec<F>>>,
        beta_prime: &[F],
    ) -> UnivariatePolynomial<F>;
}
```


#### 10. Prover-Provided Permutation Module

```rust
struct ProverProvidedPermutation<F: Field> {
    sigma: PermutationMLE<F>,
    tau: PermutationMLE<F>,  // Inverse
}

impl<F: Field> ProverProvidedPermutation<F> {
    // Compute permutation and its inverse
    fn from_functions(
        f: &MultilinearPolynomial<F>,
        g: &MultilinearPolynomial<F>,
    ) -> Result<Self, PermutationError>;
    
    // Prove τ(σ(y)) = y for all y
    fn prove_inverse(&self) -> SumcheckProof<F>;
    
    // Prove σ maps to binaries
    fn prove_binary(&self) -> SumcheckProof<F>;
    
    // Batch both checks using random linear combination
    fn prove_batched(&self, f: &MultilinearPolynomial<F>, g: &MultilinearPolynomial<F>) 
        -> ProverProvidedPermutationProof<F>;
}

struct ProverProvidedPermutationProof<F: Field> {
    sigma_commitment: Commitment,
    tau_commitment: Commitment,
    batched_permcheck: MulPermProof<F>,
    binary_check: SumcheckProof<F>,
}
```


#### 11. Lookup Argument Module

```rust
struct LookupMap {
    domain_size: usize,  // n = 2^μ
    table_size: usize,   // T = 2^κ
    mapping: Vec<usize>, // ρ: B^μ → B^κ
}

struct MulLookupProver<F: Field> {
    witness: MultilinearPolynomial<F>,  // g
    table: MultilinearPolynomial<F>,    // f
    rho: MultilinearPolynomial<F>,      // ρ̃[κ]
    domain_vars: usize,  // μ
    table_vars: usize,   // κ
}

impl<F: Field> MulLookupProver<F> {
    // Outer sumcheck over table
    fn outer_sumcheck(&mut self, s: &[F]) -> (SumcheckProof<F>, Vec<F>);
    
    // Inner sumcheck over witness using MulPerm
    fn inner_sumcheck(&mut self, alpha: &[F], s: &[F]) -> SumcheckProof<F>;
    
    fn prove(&mut self) -> MulLookupProof<F>;
}

struct MulLookupProof<F: Field> {
    outer_sumcheck: SumcheckProof<F>,
    inner_sumcheck: SumcheckProof<F>,
    table_opening: F,
    rho_openings: Vec<F>,
}
```


### Integration Layer Components

#### 12. PCS Compiler Module

```rust
trait PolynomialCommitmentScheme<F: Field> {
    type Commitment;
    type Opening;
    type Params;
    
    fn setup(max_degree: usize) -> Self::Params;
    fn commit(poly: &MultilinearPolynomial<F>, params: &Self::Params) -> Self::Commitment;
    fn open(
        poly: &MultilinearPolynomial<F>,
        point: &[F],
        params: &Self::Params,
    ) -> Self::Opening;
    fn verify(
        commitment: &Self::Commitment,
        point: &[F],
        value: F,
        opening: &Self::Opening,
        params: &Self::Params,
    ) -> bool;
    
    // Batch opening at same point
    fn batch_open(
        polys: &[MultilinearPolynomial<F>],
        point: &[F],
        params: &Self::Params,
    ) -> Self::Opening;
}

// Concrete PCS implementations
struct KZG<F: Field>;
struct Dory<F: Field>;
struct FRI<F: Field>;
struct Ligero<F: Field>;
struct Hyrax<F: Field>;
struct KZH<F: Field>;
```


## Data Models

### Core Data Structures

#### Multilinear Polynomial Representation

```
MultilinearPolynomial {
    num_vars: μ,
    evaluations: [f(0,0,...,0), f(1,0,...,0), ..., f(1,1,...,1)]
                 ↑                                    ↑
                 2^μ elements in lexicographic order
}
```

**Storage**: Dense array of 2^μ field elements
**Access Pattern**: Binary index (b₁,...,bμ) → position ∑ᵢ bᵢ·2^{i-1}
**Memory**: O(n) where n = 2^μ

#### Permutation Representation

```
Permutation {
    size: n,
    mapping: [σ(0), σ(1), ..., σ(n-1)]
}

PermutationMLE {
    num_vars: μ,
    bit_mles: [σ̃₁, σ̃₂, ..., σ̃μ]  // Each is n-sized MLE
}
```

**Storage**: Either as mapping (n integers) or as μ MLEs (μ·n field elements)
**Conversion**: O(n·μ) to compute MLEs from mapping
**Memory**: O(n·log n) for MLE representation

#### Indicator Function Representation

For BiPerm:
```
BiPermIndicator {
    sigma_L: MLE of size n^1.5 with n non-zero entries
    sigma_R: MLE of size n^1.5 with n non-zero entries
}
```

For MulPerm:
```
MulPermIndicator {
    sigma_interpolated: MLE of size n·log n
    ell: √log n
}
```


### Proof Data Structures

#### BiPerm Proof

```
BiPermProof {
    // Sumcheck proof
    round_polynomials: [u₁, u₂, ..., uμ]  // Each degree 3
    
    // Final openings
    f_eval: F(β)
    sigma_L_eval: 1̃σL(β, αL)
    sigma_R_eval: 1̃σR(β, αR)
    
    // PCS openings
    f_opening: PCS::Opening
    sigma_L_opening: PCS::Opening
    sigma_R_opening: PCS::Opening
}
```

**Size**: O(μ) = O(log n) field elements + PCS openings

#### MulPerm Proof

```
MulPermProof {
    // First sumcheck
    first_round_polynomials: [u₁, ..., uμ]  // Each degree ℓ+1
    partial_product_claims: [P₁, ..., Pℓ]
    
    // Second sumcheck
    second_round_polynomials: [v₁, ..., v_{μ+log ℓ}]  // Each degree μ/ℓ+1
    
    // Final openings
    f_eval: F(β)
    sigma_evals: [σ̃[μ](⟨i⟩, x*) for i ∈ [μ/ℓ]]
    
    // PCS openings
    f_opening: PCS::Opening
    sigma_openings: Vec<PCS::Opening>  // √log n openings
}
```

**Size**: O(μ + √μ) = O(log n) field elements + PCS openings


## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Equality Polynomial Correctness
*For any* field F and dimension μ, when computing eq(X,Y) for X,Y ∈ F^μ, the result equals ∏_{i=1}^μ [X_i Y_i + (1-X_i)(1-Y_i)], and for boolean inputs x,y ∈ B^μ, eq(x,y) = 1 if and only if x = y.

**Validates: Requirements 1.1, 1.2**

### Property 2: Multilinear Extension Correctness
*For any* function f: B^μ → F, the multilinear extension f̃ computed by the system satisfies f̃(b) = f(b) for all b ∈ B^μ and f̃(X) = ∑_{b∈B^μ} f(b) · eq(b,X) for all X ∈ F^μ.

**Validates: Requirements 1.3**

### Property 3: Sumcheck Round Consistency
*For any* μ-variate polynomial f and claimed sum v, when running sumcheck protocol, each round k produces polynomial u_k such that u_k(0) + u_k(1) equals the claimed sum from round k-1, and the protocol executes exactly μ rounds.

**Validates: Requirements 2.1, 2.2**

### Property 4: Permutation Check Correctness
*For any* functions f,g: B^μ → F and permutation σ: B^μ → B^μ, the permutation check protocol accepts if and only if f(x) = g(σ(x)) for all x ∈ B^μ.

**Validates: Requirements 3.1**

### Property 5: Sumcheck Reduction Equivalence
*For any* valid permutation σ and random challenge α ∈ F^μ, the equation ∑_{x∈B^μ} f(x) · 1̃_σ(x,α) = g(α) holds if and only if f(x) = g(σ(x)) for all x ∈ B^μ.

**Validates: Requirements 3.2**


### Property 6: BiPerm Linear Time Performance
*For any* permutation of size n = 2^μ, when BiPerm prover executes all operations including preprocessing, indicator table computation, and sumcheck rounds, the total number of field operations is O(n).

**Validates: Requirements 4.9**

### Property 7: BiPerm Correctness
*For any* valid permutation σ split into σ_L and σ_R, the BiPerm sumcheck equation ∑_{x∈B^μ} f(x) · 1̃_{σ_L}(x,α_L) · 1̃_{σ_R}(x,α_R) = g(α) holds if and only if f(x) = g(σ(x)) for all x ∈ B^μ.

**Validates: Requirements 4.5**

### Property 8: MulPerm Near-Linear Time Performance
*For any* permutation of size n = 2^μ with group parameter ℓ = √μ, when MulPerm prover executes all operations including partial product computation and both sumchecks, the total number of field operations is n · Õ(√log n).

**Validates: Requirements 5.13**

### Property 9: Bucketing Algorithm Correctness
*For any* round k in the second sumcheck of MulPerm, the bucketing algorithm produces round polynomial u_k(X) = ∑_i id_i · ∑_{x'∈bucket_i} eq((γ,X,x'),β') that equals the result of direct computation.

**Validates: Requirements 6.5, 18.9**

### Property 10: Bucketing Algorithm Performance
*For any* MulPerm execution with parameters μ and ℓ, when summing costs across all rounds using bucketing for k < log ℓ and direct computation for k ≥ log ℓ, the total field operations is n·Õ(μ/ℓ) + ℓ·2^ℓ.

**Validates: Requirements 6.12**


### Property 11: Prover-Provided Permutation Inverse Check
*For any* prover-provided permutation σ and claimed inverse τ, the protocol accepts if and only if τ(σ(y)) = y for all y ∈ B^μ.

**Validates: Requirements 7.4**

### Property 12: Binary Constraint Verification
*For any* prover-provided permutation σ̃_{[μ]}, the binary check protocol accepts if and only if σ̃_{[μ]}(i,x) ∈ {0,1} for all x ∈ B^μ and i ∈ [μ].

**Validates: Requirements 7.6**

### Property 13: Lookup Argument Correctness
*For any* witness g, table f, and map ρ: B^μ → B^κ, the lookup protocol accepts if and only if f(ρ(x)) = g(x) for all x ∈ B^μ.

**Validates: Requirements 8.2**

### Property 14: Lookup Performance for Small Tables
*For any* lookup with table size T ≤ n, the outer sumcheck executes in O(n) field operations.

**Validates: Requirements 8.7**

### Property 15: MulLookup Performance
*For any* lookup with table size T < 2^{(1-ε)μ²}, the total prover cost is n·Õ(√log T) field operations.

**Validates: Requirements 8.11**

### Property 16: Proof Size Logarithmic
*For any* permutation check using BiPerm or MulPerm, the proof size is O(log n) field elements plus PCS openings.

**Validates: Requirements 10.13**

### Property 17: Sumcheck Perfect Completeness
*For any* honest prover with valid witness, the sumcheck verifier accepts with probability 1.

**Validates: Requirements 18.3**

### Property 18: Permutation Check Soundness
*For any* invalid permutation (where f(x) ≠ g(σ(x)) for some x), the BiPerm or MulPerm verifier rejects with probability at least 1 - polylog(n)/|F|.

**Validates: Requirements 18.6**

## Error Handling

### Verification Errors

```rust
enum VerificationError {
    // Sumcheck errors
    SumcheckRoundCheckFailed { round: usize, expected: F, got: F },
    SumcheckFinalCheckFailed { expected: F, got: F },
    
    // Permutation errors
    InvalidPermutation { reason: String },
    PermutationSizeMismatch { expected: usize, got: usize },
    
    // Lookup errors
    LookupTableSizeMismatch,
    InvalidLookupMap,
    
    // PCS errors
    CommitmentVerificationFailed,
    OpeningVerificationFailed,
    
    // Parameter errors
    InvalidFieldSize,
    InvalidNumVars,
    InvalidGroupParameter,
}
```

### Input Validation

1. **Field Size**: Verify |F| ≥ 2^λ for security parameter λ
2. **Dimension**: Verify μ = log₂(n) is valid
3. **Permutation**: Verify σ is valid bijection on [n]
4. **Polynomial Degree**: Verify degrees match expected values
5. **Challenge Sampling**: Verify challenges are uniformly random

## Testing Strategy

### Unit Tests

1. **Equality Polynomial Tests**
   - Test eq(x,y) = 1 iff x = y for small μ (μ ≤ 8)
   - Test formula ∏ᵢ [XᵢYᵢ + (1-Xᵢ)(1-Yᵢ)] for random inputs
   - Test evaluate_all_boolean optimization

2. **MLE Tests**
   - Test f̃(b) = f(b) for all b ∈ B^μ
   - Test multilinearity: f̃(λx + (1-λ)y) = λf̃(x) + (1-λ)f̃(y)
   - Test partial evaluation correctness

3. **Sumcheck Tests**
   - Test round consistency: uₖ(0) + uₖ(1) = S
   - Test final verification
   - Test with various polynomial degrees

4. **Permutation Tests**
   - Test valid permutations accepted
   - Test identity permutation
   - Test cycle permutations
   - Test random permutations

### Integration Tests

1. **BiPerm Integration**
   - Test with sparse PCS (Dory, KZH)
   - Test with various n (n = 2^8, 2^16, 2^20)
   - Measure actual field operations

2. **MulPerm Integration**
   - Test with all PCS schemes
   - Test with various ℓ values
   - Verify bucketing vs direct computation equivalence

3. **Lookup Integration**
   - Test with T < n, T = n, T > n
   - Test structured tables (range proofs)
   - Test non-injective maps

### Property-Based Tests

1. **Permutation Correctness Property**
   - Generate random f, g, σ where f(x) = g(σ(x))
   - Verify protocol accepts
   - Generate random f, g, σ where f(x) ≠ g(σ(x))
   - Verify protocol rejects with high probability

2. **Bucketing Equivalence Property**
   - Generate random σ, α, challenges
   - Compute round polynomial with bucketing
   - Compute round polynomial with direct method
   - Verify results are identical

3. **Performance Properties**
   - Measure field operations for various n
   - Verify O(n) for BiPerm
   - Verify n·Õ(√log n) for MulPerm

## Performance Considerations

### Time Complexity Summary

| Protocol | Prover Time | Verifier Time | Proof Size | Soundness Error |
|----------|-------------|---------------|------------|-----------------|
| BiPerm | O(n) | O(log n) | O(log n) | O(log n/\|F\|) |
| MulPerm | n·Õ(√log n) | O(log n) | O(log n) | polylog(n)/\|F\| |
| MulLookup (T≤n) | n·Õ(√log T) | O(log n) | O(log n) | polylog(n+T)/\|F\| |

### Space Complexity

- **BiPerm**: O(n^1.5) preprocessing (sparse), O(n) runtime
- **MulPerm**: O(n log n) preprocessing, O(n) runtime
- **Sumcheck**: O(n) for evaluation tables

### Optimization Opportunities

1. **Precomputation**: Cache equality polynomial evaluations
2. **Parallelization**: Sumcheck rounds can parallelize over hypercube
3. **SIMD**: Vectorize field operations
4. **Memory Layout**: Optimize for cache locality
5. **Lazy Evaluation**: Compute partial products on-demand

## Security Considerations

### Soundness Analysis

1. **Schwartz-Zippel**: μ/|F| error for polynomial equality
2. **Sumcheck**: dμ/|F| error for degree d
3. **BiPerm Total**: O(μ/|F|) = O(log n/|F|)
4. **MulPerm Total**: O(μ^1.5/|F|) = polylog(n)/|F|

### Recommended Parameters

For λ-bit security:
- **Field Size**: |F| ≥ 2^{λ + log² n}
- **Example**: n = 2^32, λ = 128 → |F| ≥ 2^{128 + 1024} ≈ 2^{1152}
- **Practical**: Use 256-bit prime field for n ≤ 2^32

### Fiat-Shamir Security

- Hash function modeled as random oracle
- Multi-round special soundness ensures security
- Avoid super-constant round protocols (GKR vulnerability)

