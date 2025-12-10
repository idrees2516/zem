# Quasar: Sublinear Accumulation Schemes - Design Document

## Overview

Quasar is a novel multi-instance accumulation scheme achieving sublinear verifier complexity in the number of accumulated instances. The key innovation is replacing random linear combinations with partial evaluation of polynomials, reducing costly Commitment Random Linear Combination (CRC) operations from O(N) to O(√N) across all IVC steps. This design document details the architecture, algorithms, data structures, and implementation strategy for Quasar.

### Key Innovations

1. **Partial Evaluation Technique**: Uses w̃_∪(τ,X) instead of Σᵢ rᵢ·w̃ᵢ(X) to avoid O(ℓ) CRC operations
2. **Union Polynomial Construction**: Encodes all ℓ witnesses in a single polynomial w̃_∪(Y,X)
3. **Sublinear Verification**: Achieves O(log ℓ) field operations and O(1) CRC operations per step
4. **Multi-Cast Reduction**: Batches ℓ non-committed instances into one committed instance
5. **2-to-1 Folding**: Efficiently folds two accumulators using oracle batching

### Performance Characteristics

| Metric | Quasar(curve) | Quasar(code) | ProtoGalaxy | Nova |
|--------|---------------|--------------|-------------|------|
| Verifier CRC | O(1) | O(1) | O(ℓ·d) | O(1) |
| Verifier RO | O(log ℓ) | O(λ/log(1/ρ)·log ℓ) | O(1) | O(log n) |
| Total CRC (N steps) | O(√N) | O(√N) | O(N) | O(N) |
| Prover Time | O(n log n) | O(n) | O(n log n) | O(n) |
| Post-Quantum | No | Yes | No | No |

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    QUASAR ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────────────────────────────────────────────────┐    │
│  │           Multi-Instance IVC Layer                      │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │    │
│  │  │  IVC.P       │  │   IVC.V      │  │  Decider    │  │    │
│  │  │  (Prover)    │  │  (Verifier)  │  │             │  │    │
│  │  └──────────────┘  └──────────────┘  └─────────────┘  │    │
│  └────────────────────────────────────────────────────────┘    │
│                            ↓                                     │
│  ┌────────────────────────────────────────────────────────┐    │
│  │        Multi-Instance Accumulation Layer                │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │    │
│  │  │  ACC.P       │  │   ACC.V      │  │  ACC.D      │  │    │
│  │  │  (Prover)    │  │  (Verifier)  │  │  (Decider)  │  │    │
│  │  └──────────────┘  └──────────────┘  └─────────────┘  │    │
│  └────────────────────────────────────────────────────────┘    │
│                            ↓                                     │
│  ┌────────────────────────────────────────────────────────┐    │
│  │              Reduction Layer                            │    │
│  │  ┌──────────────┐              ┌──────────────┐        │    │
│  │  │ NIR_multicast│              │  NIR_fold    │        │    │
│  │  │  (Multi-Cast)│              │  (2-to-1)    │        │    │
│  │  └──────────────┘              └──────────────┘        │    │
│  └────────────────────────────────────────────────────────┘    │
│                            ↓                                     │
│  ┌────────────────────────────────────────────────────────┐    │
│  │           Polynomial Commitment Layer                   │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │    │
│  │  │ Curve-Based  │  │  Code-Based  │  │   Oracle    │  │    │
│  │  │     PCS      │  │     PCS      │  │  Batching   │  │    │
│  │  └──────────────┘  └──────────────┘  └─────────────┘  │    │
│  └────────────────────────────────────────────────────────┘    │
│                            ↓                                     │
│  ┌────────────────────────────────────────────────────────┐    │
│  │              Foundation Layer                           │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │    │
│  │  │  Sum-Check   │  │  Multilinear │  │ Fiat-Shamir │  │    │
│  │  │   Protocol   │  │  Extensions  │  │  Transform  │  │    │
│  │  └──────────────┘  └──────────────┘  └─────────────┘  │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Data Models

### Core Data Structures

```rust
/// Multi-instance IVC proof
pub struct IVCProof<F: Field> {
    /// Current step number
    pub step: usize,
    /// Initial state vector
    pub z_0: Vec<F>,
    /// Current state vector
    pub z_i: Vec<F>,
    /// Accumulator from previous step
    pub accumulator: Accumulator<F>,
    /// Proof of accumulation
    pub acc_proof: AccumulationProof<F>,
}

/// Accumulator state
pub struct Accumulator<F: Field> {
    /// Instance vector
    pub x: Vec<F>,
    /// Challenge vectors
    pub tau: Vec<F>,
    pub r_x: Vec<F>,
    pub r_F: Vec<F>,
    /// Evaluation value
    pub e: F,
    /// Polynomial commitments
    pub commitments: Vec<Commitment<F>>,
}

/// Multi-predicate tuple
pub struct MultiPredicate<F: Field> {
    /// Instance vectors for ℓ predicates
    pub instances: Vec<Vec<F>>,
    /// NARK proof
    pub proof: NARKProof<F>,
}

/// Accumulation proof
pub struct AccumulationProof<F: Field> {
    /// Multi-cast reduction proof
    pub multicast_proof: MultiCastProof<F>,
    /// 2-to-1 folding proof
    pub fold_proof: FoldProof<F>,
}
```


### Multi-Cast Reduction Data Structures

```rust
/// Multi-cast reduction proof
pub struct MultiCastProof<F: Field> {
    /// Commitment to union polynomial w̃_∪(Y,X)
    pub C_union: Commitment<F>,
    /// Commitment to batched polynomial w̃(X)
    pub C_batched: Commitment<F>,
    /// Sum-check proof for zero-check
    pub sumcheck_proof: SumCheckProof<F>,
    /// Challenge vectors
    pub tau: Vec<F>,
    pub r_x: Vec<F>,
    pub r_y: Vec<F>,
    /// Evaluation values
    pub v_union: F,
    pub v_batched: F,
}

/// Union polynomial representation
pub struct UnionPolynomial<F: Field> {
    /// Dimension parameters
    pub log_ell: usize,  // log₂(ℓ)
    pub log_n: usize,    // log₂(n)
    /// Polynomial evaluations
    pub evaluations: Vec<F>,
    /// Multilinear extension
    pub mle: MultilinearExtension<F>,
}

/// Batched polynomial after partial evaluation
pub struct BatchedPolynomial<F: Field> {
    /// Evaluation point τ
    pub tau: Vec<F>,
    /// Resulting polynomial w̃(X) = w̃_∪(τ,X)
    pub polynomial: MultilinearExtension<F>,
}
```

### 2-to-1 Reduction Data Structures

```rust
/// 2-to-1 folding proof
pub struct FoldProof<F: Field> {
    /// Batched polynomials
    pub x_batched: Vec<F>,
    pub r_F_batched: Vec<F>,
    pub tau_batched: Vec<F>,
    pub r_x_batched: Vec<F>,
    /// Message polynomials
    pub m_union_batched: Vec<MultilinearExtension<F>>,
    pub m_batched: Vec<MultilinearExtension<F>>,
    /// Sum-check proof
    pub sumcheck_proof: SumCheckProof<F>,
    /// Challenge σ
    pub sigma: F,
    /// Evaluation values
    pub eta: F,
    pub eta_i: Vec<F>,
    pub eta_union_i: Vec<F>,
    /// Oracle batching proofs
    pub batching_proofs: Vec<OracleBatchingProof<F>>,
}

/// Oracle batching proof
pub struct OracleBatchingProof<F: Field> {
    /// Batched commitment
    pub C_batched: Commitment<F>,
    /// Evaluation claims
    pub eval_claims: Vec<EvaluationClaim<F>>,
    /// PCS-specific proof
    pub pcs_proof: PCSProof<F>,
}

/// Evaluation claim
pub struct EvaluationClaim<F: Field> {
    /// Evaluation point
    pub point: Vec<F>,
    /// Claimed value
    pub value: F,
}
```

### Polynomial Commitment Schemes

```rust
/// Generic PCS trait
pub trait PolynomialCommitmentScheme<F: Field> {
    type Commitment;
    type Proof;
    type Params;
    
    fn setup(params: &Self::Params) -> Self;
    fn commit(&self, poly: &MultilinearExtension<F>) -> Self::Commitment;
    fn open(&self, poly: &MultilinearExtension<F>, point: &[F]) -> (F, Self::Proof);
    fn verify(&self, comm: &Self::Commitment, point: &[F], value: F, proof: &Self::Proof) -> bool;
    fn batch(&self, comms: &[Self::Commitment], r: F) -> Self::Commitment;
}

/// Curve-based PCS (e.g., Mercury, Bulletproofs)
pub struct CurvePCS<G: Group> {
    pub params: CurveParams<G>,
    pub generator: G,
}

/// Code-based PCS (e.g., Brakedown, Orion, BaseFold)
pub struct CodePCS<F: Field> {
    pub code: LinearCode<F>,
    pub rate: f64,
    pub merkle_root: Hash,
}

/// Linear code representation
pub struct LinearCode<F: Field> {
    /// Generator matrix
    pub generator: Vec<Vec<F>>,
    /// Message length k
    pub k: usize,
    /// Codeword length n
    pub n: usize,
    /// Minimum distance
    pub delta: f64,
}
```

## Components and Interfaces

### 1. Multi-Instance IVC Interface

```rust
pub trait MultiInstanceIVC<F: Field> {
    type Proof;
    type Accumulator;
    
    /// Initialize IVC with base case
    fn init(z_0: Vec<F>) -> Self::Accumulator;
    
    /// Prove one step with ℓ instances
    fn prove(
        &self,
        z_0: Vec<F>,
        z_i: Vec<F>,
        witnesses: Vec<Vec<F>>,
        z_i_plus_1: Vec<F>,
        acc: Self::Accumulator,
    ) -> Result<(Self::Accumulator, Self::Proof), Error>;
    
    /// Verify IVC proof
    fn verify(
        &self,
        z_0: Vec<F>,
        z_i_plus_1: Vec<F>,
        proof: &Self::Proof,
    ) -> Result<bool, Error>;
    
    /// Decide final accumulator
    fn decide(&self, acc: &Self::Accumulator) -> Result<bool, Error>;
}
```


### 2. Multi-Instance Accumulation Interface

```rust
pub trait MultiInstanceAccumulation<F: Field> {
    type Accumulator;
    type Proof;
    
    /// Accumulate ℓ predicate instances and one accumulator
    fn accumulate_prover(
        &self,
        instances: Vec<Vec<F>>,
        nark_proof: NARKProof<F>,
        acc: Self::Accumulator,
    ) -> Result<(Self::Accumulator, Self::Proof), Error>;
    
    /// Verify accumulation step
    fn accumulate_verifier(
        &self,
        instances: Vec<Vec<F>>,
        nark_instance: Vec<F>,
        acc_instance: Vec<F>,
    ) -> Result<bool, Error>;
    
    /// Decide final accumulator
    fn decide(
        &self,
        acc: Self::Accumulator,
    ) -> Result<bool, Error>;
}
```

### 3. Multi-Cast Reduction Interface

```rust
pub trait MultiCastReduction<F: Field> {
    type Proof;
    
    /// Reduce ℓ instances to one committed instance
    fn reduce_prover(
        &self,
        instances: Vec<Vec<F>>,
        witnesses: Vec<Vec<F>>,
    ) -> Result<(Vec<F>, Vec<F>, Self::Proof), Error>;
    
    /// Verify multi-cast reduction
    fn reduce_verifier(
        &self,
        instances: Vec<Vec<F>>,
        reduced_instance: Vec<F>,
        proof: &Self::Proof,
    ) -> Result<bool, Error>;
    
    /// Compute union polynomial
    fn compute_union_polynomial(
        &self,
        witnesses: Vec<Vec<F>>,
    ) -> UnionPolynomial<F>;
    
    /// Perform partial evaluation
    fn partial_evaluate(
        &self,
        union_poly: &UnionPolynomial<F>,
        tau: &[F],
    ) -> BatchedPolynomial<F>;
}
```

### 4. 2-to-1 Reduction Interface

```rust
pub trait TwoToOneReduction<F: Field> {
    type Proof;
    
    /// Fold two accumulators into one
    fn fold_prover(
        &self,
        acc_0: Accumulator<F>,
        acc_1: Accumulator<F>,
    ) -> Result<(Accumulator<F>, Self::Proof), Error>;
    
    /// Verify 2-to-1 folding
    fn fold_verifier(
        &self,
        acc_0_instance: Vec<F>,
        acc_1_instance: Vec<F>,
        acc_new_instance: Vec<F>,
        proof: &Self::Proof,
    ) -> Result<bool, Error>;
    
    /// Batch polynomials
    fn batch_polynomials(
        &self,
        polys: Vec<MultilinearExtension<F>>,
        challenge: F,
    ) -> MultilinearExtension<F>;
}
```

### 5. Oracle Batching Interface

```rust
pub trait OracleBatching<F: Field> {
    type Proof;
    
    /// Batch two polynomial oracles
    fn batch_prover(
        &self,
        poly_0: &MultilinearExtension<F>,
        poly_1: &MultilinearExtension<F>,
        r: F,
        x: &[F],
        v: F,
    ) -> Result<(MultilinearExtension<F>, Vec<EvaluationClaim<F>>, Self::Proof), Error>;
    
    /// Verify oracle batching
    fn batch_verifier(
        &self,
        comm_0: &Commitment<F>,
        comm_1: &Commitment<F>,
        r: F,
        x: &[F],
        v: F,
        eval_claims: &[EvaluationClaim<F>],
        proof: &Self::Proof,
    ) -> Result<bool, Error>;
}
```

## Algorithms

### Algorithm 1: Multi-Cast Reduction Prover

```
Input: 
  - Instances {x^(k)}_{k∈[ℓ]}
  - Witnesses {w^(k)}_{k∈[ℓ]}
  - Constraint function F

Output:
  - Reduced instance x
  - Reduced witness w
  - Proof π_multicast

Steps:
1. Compute multilinear extensions:
   For k ∈ [ℓ]:
     w̃^(k)(X) ← MLE(w^(k))
     x̃^(k)(X) ← MLE(x^(k))

2. Compute union polynomial:
   w̃_∪(Y,X) ← Σ_{k∈[ℓ]} eq̃_{k-1}(Y) · w̃^(k)(X)
   x̃_∪(Y,X) ← Σ_{k∈[ℓ]} eq̃_{k-1}(Y) · x̃^(k)(X)

3. Commit to union polynomial:
   C_∪ ← PCS.Commit(w̃_∪)

4. Sample challenge τ ← F^{log ℓ} (via Fiat-Shamir)

5. Compute batched polynomial:
   w̃(X) ← w̃_∪(τ,X)
   x̃(X) ← x̃_∪(τ,X)

6. Commit to batched polynomial:
   C ← PCS.Commit(w̃)

7. Sample challenge r_y ← F^{log ℓ} (via Fiat-Shamir)

8. Compute constraint polynomial:
   G(Y) ← F(x̃(Y), w̃(Y)) · eq̃(Y, r_y)

9. Run sum-check protocol:
   π_sumcheck ← SumCheck.Prove(Σ_{y∈B^{log ℓ}} G(y) = 0)
   Extract final challenge τ from sum-check

10. Sample challenge r_x ← F^{log n} (via Fiat-Shamir)

11. Compute evaluation values:
    v_∪ ← w̃_∪(τ, r_x)
    v ← w̃(r_x)

12. Compute reduced instance:
    x ← Σ_{k∈[ℓ]} eq̃_{k-1}(τ) · x^(k)
    e ← G_{log ℓ}(τ_{log ℓ}) · eq̃^{-1}(τ, r_y)

13. Return:
    x ← (x, τ, r_x, e)
    w ← w̃
    π_multicast ← (C_∪, C, π_sumcheck, v_∪, v)
```


### Algorithm 2: Multi-Cast Reduction Verifier

```
Input:
  - Instances {x^(k)}_{k∈[ℓ]}
  - Reduced instance x = (x, τ, r_x, e)
  - Proof π_multicast = (C_∪, C, π_sumcheck, v_∪, v)

Output:
  - Accept/Reject

Steps:
1. Compute batched instance:
   x ← Σ_{k∈[ℓ]} eq̃_{k-1}(τ) · x^(k)
   Verify x matches claimed value

2. Verify sum-check proof:
   (accept, G_{log ℓ}(τ_{log ℓ})) ← SumCheck.Verify(π_sumcheck)
   If not accept, return Reject

3. Verify constraint:
   e_computed ← G_{log ℓ}(τ_{log ℓ}) · eq̃^{-1}(τ, r_y)
   If e ≠ e_computed, return Reject

4. Verify partial evaluation:
   If v_∪ ≠ v, return Reject

5. Return Accept
```

### Algorithm 3: 2-to-1 Reduction Prover

```
Input:
  - Two accumulators acc^(0), acc^(1)
  - Each acc^(k) = (x^(k), τ^(k), r_x^(k), r_F^(k), e^(k), {C_∪,i^(k), C_i^(k)}_{i∈[μ]})

Output:
  - New accumulator acc
  - Proof π_fold

Steps:
1. Compute batched polynomials:
   x̃(Z) ← Σ_{k∈{0,1}} eq̃_k(Z) · x^(k)
   r̃_F(Z) ← Σ_{k∈{0,1}} eq̃_k(Z) · r_F^(k)
   τ̃(Z) ← Σ_{k∈{0,1}} eq̃_k(Z) · τ^(k)
   r̃_x(Z) ← Σ_{k∈{0,1}} eq̃_k(Z) · r_x^(k)
   For i ∈ [μ]:
     m̃_∪,i(Z) ← Σ_{k∈{0,1}} eq̃_k(Z) · m_∪^(k)
     m̃_i(Z) ← Σ_{k∈{0,1}} eq̃_k(Z) · m_i^(k)

2. Sample challenge γ ← F^{log(μ+1)} (via Fiat-Shamir)

3. Sample challenge r_z ← F (via Fiat-Shamir)

4. Compute combined polynomial:
   G(Z) ← eq̃(r_z, Z) · (F(x̃(Z), {m_i(Z)}_{i∈[μ]}, r̃_F(Z)) - ẽ(Z))
        + Σ_{i∈[μ]} pow_i(γ) · (m̃_i(Z, r̃_x(Z)) - ṽ_i(Z))
        + Σ_{i∈[μ]} pow_{μ+i}(γ) · (m̃_∪,i(Z, τ̃(Z), r̃_x(Z)) - ṽ_i(Z))

5. Run 1-round sum-check:
   Send G(Z) to verifier
   Verify G(0) + G(1) = 0

6. Sample challenge σ ← F (via Fiat-Shamir)

7. Compute evaluation values:
   η ← F(x̃(σ), {m_i(σ)}_{i∈[μ]}, r̃_F(σ)) - ẽ(σ)
   For i ∈ [μ]:
     η_i ← m̃_i(σ, r̃_x(σ)) - ṽ_i(σ)
     η_∪,i ← m̃_∪,i(σ, τ̃(σ), r̃_x(σ)) - ṽ_i(σ)

8. Verify G(σ):
   G_σ ← eq̃(r_z, σ) · (η + Σ_{i∈[μ]} pow_i(γ)·η_i + Σ_{i∈[μ]} pow_{μ+i}(γ)·η_∪,i)
   If G(σ) ≠ G_σ, abort

9. Run 2μ oracle batching protocols in parallel:
   For i ∈ [μ]:
     (m̃_∪,i, claims_∪,i, π_batch_∪,i) ← OracleBatch.Prove(m̃_∪,i^(0), m̃_∪,i^(1), σ)
     (m̃_i, claims_i, π_batch_i) ← OracleBatch.Prove(m̃_i^(0), m̃_i^(1), σ)

10. Compute new accumulator:
    x ← x̃(σ)
    τ ← τ̃(σ)
    r_x ← r̃_x(σ)
    r_F ← r̃_F(σ)
    e ← ẽ(σ)
    acc ← (x, τ, r_x, r_F, e, {m̃_∪,i, m̃_i}_{i∈[μ]})

11. Return:
    acc
    π_fold ← (G(Z), σ, η, {η_i, η_∪,i}_{i∈[μ]}, {π_batch_∪,i, π_batch_i}_{i∈[μ]})
```

### Algorithm 4: 2-to-1 Reduction Verifier

```
Input:
  - Two accumulator instances acc^(0).x, acc^(1).x
  - New accumulator instance acc.x
  - Proof π_fold

Output:
  - Accept/Reject

Steps:
1. Verify sum-check:
   Extract G(Z) from π_fold
   If G(0) + G(1) ≠ 0, return Reject

2. Verify G(σ) evaluation:
   Compute G_σ from η, {η_i, η_∪,i}_{i∈[μ]}
   If G(σ) ≠ G_σ, return Reject

3. Verify oracle batching proofs:
   For i ∈ [μ]:
     If not OracleBatch.Verify(π_batch_∪,i), return Reject
     If not OracleBatch.Verify(π_batch_i), return Reject

4. Return Accept
```


### Algorithm 5: Multi-Instance IVC Prover

```
Input:
  - Initial state z_0
  - Current state z_i
  - Witnesses {w_k}_{k∈[ℓ]}
  - Next state z_{i+1}
  - Previous accumulator acc_i

Output:
  - New accumulator acc_{i+1}
  - IVC proof Π_{i+1}

Steps:
1. For each k ∈ [ℓ]:
   Verify predicate: φ(z_0, z_i[k], z_{i+1}[k], w_k) = 1
   If not satisfied, abort

2. Arithmetize predicates:
   For k ∈ [ℓ]:
     (i', x'^(k), w'^(k)) ← Arithmetize(φ, z_0, z_i[k], z_{i+1}[k], w_k)

3. Generate NARK proof:
   π_nark ← NARK.Prove({x'^(k), w'^(k)}_{k∈[ℓ]})

4. Create multi-predicate tuple:
   multi_pred ← ({x'^(k)}_{k∈[ℓ]}, π_nark.x)

5. Run accumulation prover:
   (acc_{i+1}, π_acc) ← ACC.P(multi_pred, π_nark, acc_i)

6. Return:
   acc_{i+1}
   Π_{i+1} ← (z_0, z_{i+1}, acc_{i+1}, π_acc)
```

### Algorithm 6: Multi-Instance IVC Verifier

```
Input:
  - Initial state z_0
  - Final state z_{i+1}
  - IVC proof Π_{i+1}

Output:
  - Accept/Reject

Steps:
1. Extract accumulator instance:
   acc.x ← Π_{i+1}.acc_{i+1}.x

2. Verify accumulation proof:
   If not ACC.V(acc.x, Π_{i+1}.π_acc), return Reject

3. Return Accept
```

### Algorithm 7: Decider

```
Input:
  - Final accumulator acc

Output:
  - Accept/Reject

Steps:
1. Extract evaluation claims:
   For i ∈ [μ]:
     claims_∪,i ← Extract claims from m̃_∪,i
     claims_i ← Extract claims from m̃_i

2. Verify all evaluation claims:
   For each claim (point, value, commitment):
     If not PCS.Verify(commitment, point, value), return Reject

3. Verify constraint:
   If F(acc.x, {m_i(acc.r_x)}_{i∈[μ]}, acc.r_F) ≠ acc.e, return Reject

4. Verify partial evaluations:
   For i ∈ [μ]:
     If m̃_∪,i(acc.τ, acc.r_x) ≠ m̃_i(acc.r_x), return Reject

5. Return Accept
```

### Algorithm 8: Oracle Batching (Homomorphic PCS)

```
Input:
  - Two commitments C_0, C_1
  - Challenge r ∈ F
  - Evaluation point x
  - Claimed value v

Output:
  - Batched commitment C
  - Evaluation claims
  - Proof π_batch

Steps:
1. Compute batched commitment:
   C ← eq̃_0(r) · C_0 + eq̃_1(r) · C_1

2. Verify evaluation:
   If eq̃_0(r) · f̃_0(x) + eq̃_1(r) · f̃_1(x) ≠ v, abort

3. Return:
   C
   claims ← [(x, v)]
   π_batch ← ∅  // No additional proof needed for homomorphic PCS
```

### Algorithm 9: Oracle Batching (Code-Based PCS)

```
Input:
  - Two codewords u_0, u_1
  - Challenge r ∈ F
  - Evaluation point x
  - Claimed value v

Output:
  - Batched codeword u
  - Evaluation claims
  - Proof π_batch

Steps:
1. Encode multilinear polynomials:
   For i ∈ {0,1}:
     u_i ← C(f_i)  // Systematic linear code

2. Compute batched codeword:
   u ← eq̃_0(r) · u_0 + eq̃_1(r) · u_1

3. Sample out-of-domain point:
   α ← F^{log n} \ {0,1}^{log n}

4. Compute evaluations:
   For i ∈ {0,1}:
     ũ_i(α) ← OutOfDomainSample(u_i, α)
   ũ(α) ← OutOfDomainSample(u, α)

5. Verify batching:
   If eq̃_0(r) · ũ_0(α) + eq̃_1(r) · ũ_1(α) ≠ ũ(α), abort

6. Proximity testing:
   π_prox ← ProximityTest(u, C, δ)

7. Return:
   u
   claims ← [(x, v), (α, ũ(α))]
   π_batch ← (ũ_0(α), ũ_1(α), ũ(α), π_prox)
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Multi-Cast Partial Evaluation Correctness

*For any* ℓ witness vectors {w^(k)}_{k∈[ℓ]} and challenge τ ∈ F^{log ℓ}, the partial evaluation w̃(X) = w̃_∪(τ,X) should equal the batched witness Σ_{k∈[ℓ]} eq̃_{k-1}(τ) · w̃^(k)(X)

**Validates: Requirements 3.2, 3.3, 3.4**

### Property 2: Accumulation Completeness

*For any* valid multi-predicate tuple and accumulator, an honest accumulation prover should always produce an accepting proof

**Validates: Requirements 1.5, 11.1**

### Property 3: Accumulation Knowledge Soundness

*For any* successful accumulation prover, there exists an extractor that can extract valid witnesses for all accumulated instances

**Validates: Requirements 1.6, 11.2, 11.3**

### Property 4: Sublinear Verifier Complexity

*For any* accumulation step with ℓ instances, the verifier should perform at most O(log ℓ) field operations and O(1) CRC operations

**Validates: Requirements 2.1, 2.2, 2.3, 2.4**

### Property 5: 2-to-1 Folding Correctness

*For any* two valid accumulators, the 2-to-1 reduction should produce a new accumulator that preserves all accumulated instances

**Validates: Requirements 4.1, 4.2, 4.9**

### Property 6: Sum-Check Soundness

*For any* polynomial G(Y) with degree d, if Σ_{y∈B^{log ℓ}} G(y) ≠ 0, then the sum-check verifier should reject except with probability at most (log ℓ · d)/|F|

**Validates: Requirements 3.7, 11.6**

### Property 7: Oracle Batching Succinctness

*For any* two polynomial oracles of size n, the batching proof should have size o(n)

**Validates: Requirements 6.4, 6.9, 6.10**

### Property 8: IVC Completeness

*For any* valid sequence of computation steps, an honest IVC prover should always produce an accepting proof

**Validates: Requirements 1.5, 11.1**

### Property 9: IVC Knowledge Soundness

*For any* successful IVC prover, there exists an extractor that can extract valid witnesses for all computation steps

**Validates: Requirements 1.6, 11.2**

### Property 10: Linear-Time Prover

*For any* witness of size n, when using linear-time-encodable codes, the accumulation prover should run in O(n) time

**Validates: Requirements 7.1, 7.2, 7.3**


### Property 11: Post-Quantum Security

*For any* quantum adversary with polynomial-time quantum algorithms, when using code-based PCS, the accumulation scheme should remain secure

**Validates: Requirements 8.1, 8.2**

### Property 12: Constant Verification (Curve-Based)

*For any* accumulation step using curve-based PCS, the verifier should perform O(1) group operations

**Validates: Requirements 9.1, 9.2**

### Property 13: Fiat-Shamir Security

*For any* interactive protocol compiled with Fiat-Shamir, the non-interactive version should satisfy RBR knowledge soundness in the random oracle model

**Validates: Requirements 10.1, 10.2, 10.5**

### Property 14: Parallelizable Proving

*For any* accumulation step, the prover should be able to compute union polynomials for different instances in parallel

**Validates: Requirements 14.1, 14.2, 14.3**

### Property 15: Memory Efficiency

*For any* witness of size n, the prover should use at most O(n) memory

**Validates: Requirements 15.1, 15.4, 15.9**

## Error Handling

### Error Types

```rust
#[derive(Debug, Clone)]
pub enum QuasarError {
    /// Invalid parameter error
    InvalidParameter(String),
    
    /// Field size too small for security
    InsufficientFieldSize { required: usize, actual: usize },
    
    /// Polynomial degree exceeds bound
    DegreeExceeded { max: usize, actual: usize },
    
    /// Malformed proof
    MalformedProof(String),
    
    /// Verification failure
    VerificationFailed(String),
    
    /// Sum-check verification failed
    SumCheckFailed { round: usize, reason: String },
    
    /// Evaluation mismatch
    EvaluationMismatch { expected: String, actual: String },
    
    /// Commitment verification failed
    CommitmentVerificationFailed(String),
    
    /// Code parameter error
    InvalidCodeParameters { rate: f64, min_distance: f64 },
    
    /// Challenge set too small
    InsufficientChallengeSetSize { required: usize, actual: usize },
    
    /// Out of memory
    OutOfMemory { requested: usize, available: usize },
    
    /// Timeout
    Timeout { operation: String, duration_ms: u64 },
    
    /// PCS error
    PCSError(String),
    
    /// Serialization error
    SerializationError(String),
}

impl std::fmt::Display for QuasarError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            QuasarError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            QuasarError::InsufficientFieldSize { required, actual } => 
                write!(f, "Field size {} too small, need at least {}", actual, required),
            QuasarError::DegreeExceeded { max, actual } => 
                write!(f, "Polynomial degree {} exceeds maximum {}", actual, max),
            QuasarError::MalformedProof(msg) => write!(f, "Malformed proof: {}", msg),
            QuasarError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            QuasarError::SumCheckFailed { round, reason } => 
                write!(f, "Sum-check failed at round {}: {}", round, reason),
            QuasarError::EvaluationMismatch { expected, actual } => 
                write!(f, "Evaluation mismatch: expected {}, got {}", expected, actual),
            QuasarError::CommitmentVerificationFailed(msg) => 
                write!(f, "Commitment verification failed: {}", msg),
            QuasarError::InvalidCodeParameters { rate, min_distance } => 
                write!(f, "Invalid code parameters: rate={}, min_distance={}", rate, min_distance),
            QuasarError::InsufficientChallengeSetSize { required, actual } => 
                write!(f, "Challenge set size {} too small, need at least {}", actual, required),
            QuasarError::OutOfMemory { requested, available } => 
                write!(f, "Out of memory: requested {} bytes, only {} available", requested, available),
            QuasarError::Timeout { operation, duration_ms } => 
                write!(f, "Operation '{}' timed out after {} ms", operation, duration_ms),
            QuasarError::PCSError(msg) => write!(f, "PCS error: {}", msg),
            QuasarError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for QuasarError {}
```

### Validation Functions

```rust
/// Validate field size for security
pub fn validate_field_size(field_size: usize, security_bits: usize) -> Result<(), QuasarError> {
    let required_size = 2_usize.pow(security_bits as u32);
    if field_size < required_size {
        return Err(QuasarError::InsufficientFieldSize {
            required: required_size,
            actual: field_size,
        });
    }
    Ok(())
}

/// Validate polynomial degree
pub fn validate_degree(degree: usize, max_degree: usize) -> Result<(), QuasarError> {
    if degree > max_degree {
        return Err(QuasarError::DegreeExceeded {
            max: max_degree,
            actual: degree,
        });
    }
    Ok(())
}

/// Validate code parameters
pub fn validate_code_parameters(rate: f64, min_distance: f64) -> Result<(), QuasarError> {
    if rate <= 0.0 || rate >= 1.0 {
        return Err(QuasarError::InvalidCodeParameters { rate, min_distance });
    }
    if min_distance <= 0.0 || min_distance >= 1.0 {
        return Err(QuasarError::InvalidCodeParameters { rate, min_distance });
    }
    Ok(())
}

/// Validate challenge set size
pub fn validate_challenge_set_size(size: usize, security_bits: usize) -> Result<(), QuasarError> {
    let required_size = 2_usize.pow(security_bits as u32);
    if size < required_size {
        return Err(QuasarError::InsufficientChallengeSetSize {
            required: required_size,
            actual: size,
        });
    }
    Ok(())
}
```

## Testing Strategy

### Unit Tests

1. **Multilinear Extension Tests**
   - Test MLE computation for various input sizes
   - Verify evaluation at Boolean hypercube points
   - Test partial evaluation correctness

2. **Union Polynomial Tests**
   - Test union polynomial construction for ℓ = 2, 4, 8, 16
   - Verify eq̃_k(Y) computation
   - Test batching via partial evaluation

3. **Sum-Check Protocol Tests**
   - Test sum-check for polynomials of various degrees
   - Verify round polynomial generation
   - Test verifier checks at each round

4. **Commitment Tests**
   - Test curve-based commitment and opening
   - Test code-based commitment and proximity testing
   - Verify batching for both PCS types

5. **Oracle Batching Tests**
   - Test batching two polynomials
   - Verify evaluation claims
   - Test succinctness property

### Property-Based Tests

1. **Property Test: Multi-Cast Correctness**
   - **Feature: quasar, Property 1: Multi-Cast Partial Evaluation Correctness**
   - Generate random ℓ witness vectors
   - Compute union polynomial and partial evaluation
   - Verify w̃(X) = Σ_{k∈[ℓ]} eq̃_{k-1}(τ) · w̃^(k)(X)

2. **Property Test: Accumulation Completeness**
   - **Feature: quasar, Property 2: Accumulation Completeness**
   - Generate random valid multi-predicate tuples
   - Run accumulation prover
   - Verify accumulation verifier accepts

3. **Property Test: Sublinear Verifier**
   - **Feature: quasar, Property 4: Sublinear Verifier Complexity**
   - Generate accumulation steps with varying ℓ
   - Count field operations and CRC operations
   - Verify O(log ℓ) and O(1) bounds

4. **Property Test: 2-to-1 Folding**
   - **Feature: quasar, Property 5: 2-to-1 Folding Correctness**
   - Generate two random valid accumulators
   - Run 2-to-1 reduction
   - Verify new accumulator preserves all instances

5. **Property Test: Sum-Check Soundness**
   - **Feature: quasar, Property 6: Sum-Check Soundness**
   - Generate random polynomials with non-zero sum
   - Run sum-check protocol
   - Verify rejection probability bounds

6. **Property Test: Oracle Batching Succinctness**
   - **Feature: quasar, Property 7: Oracle Batching Succinctness**
   - Generate two random polynomials of size n
   - Run oracle batching
   - Verify proof size is o(n)

7. **Property Test: IVC Completeness**
   - **Feature: quasar, Property 8: IVC Completeness**
   - Generate random valid computation sequences
   - Run IVC prover for multiple steps
   - Verify IVC verifier accepts

8. **Property Test: Linear-Time Prover**
   - **Feature: quasar, Property 10: Linear-Time Prover**
   - Generate witnesses of varying sizes
   - Measure prover time
   - Verify O(n) scaling

9. **Property Test: Parallelizable Proving**
   - **Feature: quasar, Property 14: Parallelizable Proving**
   - Generate multiple instances
   - Run prover with different thread counts
   - Verify speedup with parallelization

10. **Property Test: Memory Efficiency**
    - **Feature: quasar, Property 15: Memory Efficiency**
    - Generate witnesses of varying sizes
    - Measure peak memory usage
    - Verify O(n) memory bound


## Implementation Plan

### Phase 1: Foundation (Weeks 1-2)

#### 1.1 Field and Polynomial Arithmetic
- Implement field operations for Goldilocks, M61, and BN254 scalar fields
- Implement multilinear extension computation
- Implement equality polynomial eq̃(X,Y)
- Implement polynomial evaluation and partial evaluation

#### 1.2 Sum-Check Protocol
- Implement sum-check prover with dynamic programming
- Implement sum-check verifier
- Implement round polynomial generation
- Add Fiat-Shamir transformation

### Phase 2: Polynomial Commitment Schemes (Weeks 3-4)

#### 2.1 Curve-Based PCS
- Implement Pedersen commitment scheme
- Implement Mercury PCS with constant proof size
- Implement homomorphic batching
- Add commitment serialization

#### 2.2 Code-Based PCS
- Implement systematic linear codes
- Implement Reed-Solomon codes
- Implement Brakedown/Orion encoding
- Implement proximity testing
- Implement out-of-domain sampling
- Add Merkle tree commitments (BCS transform)

### Phase 3: Multi-Cast Reduction (Weeks 5-6)

#### 3.1 Union Polynomial Construction
- Implement union polynomial w̃_∪(Y,X) computation
- Optimize for large ℓ using streaming
- Add parallelization for multiple instances
- Implement memory-efficient storage

#### 3.2 Partial Evaluation
- Implement partial evaluation w̃_∪(τ,X)
- Optimize evaluation using precomputation
- Add caching for repeated evaluations

#### 3.3 Multi-Cast Prover and Verifier
- Implement multi-cast reduction prover
- Implement multi-cast reduction verifier
- Add constraint verification
- Integrate with sum-check protocol

### Phase 4: 2-to-1 Reduction (Weeks 7-8)

#### 4.1 Polynomial Batching
- Implement batched polynomial computation
- Optimize for multiple polynomials
- Add parallel batching

#### 4.2 Oracle Batching
- Implement homomorphic oracle batching
- Implement code-based oracle batching
- Add proximity testing for batched codewords
- Optimize for 2μ parallel batching operations

#### 4.3 2-to-1 Prover and Verifier
- Implement 2-to-1 reduction prover
- Implement 2-to-1 reduction verifier
- Add sum-check integration
- Optimize accumulator folding

### Phase 5: Multi-Instance Accumulation (Weeks 9-10)

#### 5.1 Accumulator Data Structures
- Implement accumulator state management
- Add accumulator serialization
- Implement accumulator compression

#### 5.2 Accumulation Prover
- Implement multi-instance accumulation prover
- Integrate multi-cast and 2-to-1 reductions
- Add NARK proof generation
- Optimize for large ℓ

#### 5.3 Accumulation Verifier and Decider
- Implement accumulation verifier
- Implement decider algorithm
- Add evaluation claim verification
- Optimize verification complexity

### Phase 6: Multi-Instance IVC (Weeks 11-12)

#### 6.1 IVC Prover
- Implement IVC prover algorithm
- Add predicate arithmetization
- Integrate with accumulation scheme
- Add recursive circuit generation

#### 6.2 IVC Verifier
- Implement IVC verifier algorithm
- Add proof verification
- Optimize verification time

#### 6.3 Special-Sound Protocol Integration
- Implement HyperPlonk constraint system
- Add gate identity verification
- Add wiring identity verification
- Add instance consistency checks

### Phase 7: Optimizations (Weeks 13-14)

#### 7.1 Parallelization
- Add parallel union polynomial computation
- Add parallel sum-check rounds
- Add parallel oracle batching
- Implement work-stealing scheduler

#### 7.2 Memory Optimization
- Implement streaming prover
- Add memory-mapped witness storage
- Implement arena allocation
- Add memory pools

#### 7.3 SIMD and Hardware Acceleration
- Add AVX-512 field operations
- Implement GPU polynomial operations
- Optimize NTT computations

### Phase 8: Integration and Testing (Weeks 15-16)

#### 8.1 zkVM Integration
- Create adapters for existing NARK systems
- Add HyperPlonk integration
- Add R1CS integration
- Create example applications

#### 8.2 Comprehensive Testing
- Implement all unit tests
- Implement all property-based tests
- Add integration tests
- Add benchmarks

#### 8.3 Documentation and Examples
- Write API documentation
- Create usage examples
- Write integration guide
- Add performance tuning guide

## Security Considerations

### 1. Soundness Error Analysis

The total soundness error ε_total is bounded by:

```
ε_total ≤ ε_sumcheck + ε_partial_eval + ε_batching + ε_pcs

where:
- ε_sumcheck ≤ (log ℓ · d) / |F|
- ε_partial_eval ≤ log n / |F|
- ε_batching ≤ 2μ · ε_batch_single
- ε_pcs depends on PCS instantiation
```

For 128-bit security with |F| = 2^64:
- Choose log ℓ ≤ 20, d ≤ 10: ε_sumcheck ≤ 200/2^64 ≈ 2^{-57}
- Choose log n ≤ 30: ε_partial_eval ≤ 30/2^64 ≈ 2^{-59}
- Choose μ ≤ 10: ε_batching ≤ 20 · ε_batch_single

Total error: ε_total ≈ 2^{-56} (negligible for 128-bit security)

### 2. Challenge Set Size

For RBR knowledge soundness, challenge sets must have size at least 2^λ:
- Field size |F| ≥ 2^128 for 128-bit security
- Use extension fields if base field is too small
- Goldilocks field requires F_{q^2} extension

### 3. Code Parameters

For code-based PCS with post-quantum security:
- Code rate ρ ≥ 1/2 for efficiency
- Minimum distance δ ≥ 0.1 for soundness
- List decoding radius τ < δ/2
- Security parameter λ ≥ 128

### 4. Fiat-Shamir Security

To ensure ROM security:
- Use collision-resistant hash functions (SHA-3, BLAKE3)
- Include all previous transcript in hash input
- Use domain separation for different protocol phases
- Ensure sufficient hash output length (≥ 2λ bits)

### 5. Side-Channel Resistance

For production deployments:
- Use constant-time field operations
- Avoid data-dependent branches
- Use constant-time polynomial evaluation
- Implement blinding for sensitive operations

## Performance Optimization Strategies

### 1. Precomputation

- Precompute eq̃_k(Y) for common k values
- Cache Lagrange basis polynomials
- Precompute NTT twiddle factors
- Store frequently used evaluation points

### 2. Batch Processing

- Batch multiple sum-check rounds
- Batch oracle batching operations
- Batch commitment operations
- Batch field operations using SIMD

### 3. Memory Layout

- Use cache-friendly data structures
- Align data to cache line boundaries
- Use structure-of-arrays for polynomials
- Minimize memory allocations

### 4. Parallelization Strategy

- Parallelize union polynomial computation across instances
- Parallelize sum-check round polynomial evaluation
- Parallelize oracle batching operations
- Use thread pools to avoid thread creation overhead

### 5. Streaming Computation

- Process witnesses in chunks
- Use memory-mapped files for large data
- Implement incremental polynomial evaluation
- Minimize peak memory usage

## Concrete Instantiations

### Quasar(curve) - Elliptic Curve Based

**Parameters:**
- Field: BN254 scalar field (254 bits)
- PCS: Mercury (constant proof size)
- Constraint System: HyperPlonk
- Security: 128-bit (classical)

**Performance:**
- Prover Time: O(n log n)
- Verifier Time: O(log ℓ) field ops + O(1) group ops
- Proof Size: O(log ℓ) field elements + O(1) group elements
- Memory: O(n)

**Use Cases:**
- Production zkVMs requiring fast verification
- Applications with moderate witness sizes
- Systems prioritizing verifier efficiency

### Quasar(code) - Linear Code Based

**Parameters:**
- Field: Goldilocks (64 bits) with F_{q^2} extension
- PCS: Brakedown (linear-time encoding)
- Code: Reed-Solomon with rate ρ = 1/2
- Constraint System: HyperPlonk
- Security: 128-bit (post-quantum)

**Performance:**
- Prover Time: O(n)
- Verifier Time: O(λ/log(1/ρ) · (log n + log ℓ)) RO queries
- Proof Size: O(λ/log(1/ρ) · log n) hash values
- Memory: O(n)

**Use Cases:**
- Post-quantum secure applications
- Large-scale computations requiring linear prover
- Systems with abundant prover resources
- Applications requiring transparent setup

## Comparison with Existing Systems

| System | Verifier CRC | Total CRC (N steps) | Prover Time | Post-Quantum |
|--------|--------------|---------------------|-------------|--------------|
| Nova | O(1) | O(N) | O(n) | No |
| HyperNova | O(1) | O(N) | O(n) | No |
| ProtoGalaxy | O(ℓ·d) | O(N) | O(n log n) | No |
| KiloNova | O(ℓ) | O(N) | O(n) | No |
| Arc | O(ℓ) | O(N) | O(n log n) | Yes |
| WARP | O(ℓ) | O(N) | O(n) | Yes |
| **Quasar(curve)** | **O(1)** | **O(√N)** | **O(n log n)** | **No** |
| **Quasar(code)** | **O(1)** | **O(√N)** | **O(n)** | **Yes** |

**Key Advantages:**
1. **Sublinear Total CRC**: O(√N) vs O(N) in all existing systems
2. **Constant Verifier CRC**: O(1) vs O(ℓ) or O(ℓ·d) in multi-instance schemes
3. **Flexible Instantiation**: Both curve-based and code-based options
4. **Post-Quantum Option**: Quasar(code) provides plausible post-quantum security
5. **Linear Prover Option**: Quasar(code) achieves O(n) prover time

## Conclusion

Quasar represents a significant advancement in multi-instance accumulation schemes, achieving sublinear verifier complexity through the novel use of partial evaluation. The design provides:

1. **Theoretical Improvement**: O(√N) total CRC operations vs O(N) in existing systems
2. **Practical Efficiency**: O(1) CRC operations per step enables efficient recursive circuits
3. **Flexibility**: Support for both curve-based and code-based PCS
4. **Post-Quantum Security**: Code-based instantiation provides plausible post-quantum security
5. **Linear-Time Prover**: Code-based instantiation achieves O(n) prover complexity
6. **Production Ready**: Comprehensive error handling, testing, and optimization strategies

The implementation plan provides a clear path to a production-ready system over 16 weeks, with careful attention to correctness, security, and performance.
