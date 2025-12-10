# Quasar: Sublinear Accumulation Schemes - Comprehensive Design Document

## Executive Summary

Quasar is a groundbreaking multi-instance accumulation scheme that achieves **sublinear verifier complexity** in the number of accumulated instances. The core innovation replaces expensive random linear combinations with **partial evaluation of polynomials**, reducing Commitment Random Linear Combination (CRC) operations from O(N) to O(√N) across all IVC steps.

### Revolutionary Impact

**Problem Solved:** Existing IVC/PCD systems suffer from linear recursion overhead:
- Nova/HyperNova: O(N) CRC operations across N steps
- ProtoGalaxy: O(ℓ·d) CRC operations per step with ℓ instances
- KiloNova: O(ℓ) CRC operations per step

**Quasar Solution:**
- **O(1) CRC operations per step** (constant!)
- **O(√N) total CRC operations** across all steps
- **O(log ℓ) field operations** in verifier
- Enables practical multi-instance IVC with minimal recursion overhead

### Key Metrics

| Metric | Quasar | ProtoGalaxy | Nova | Improvement |
|--------|--------|-------------|------|-------------|
| Verifier CRC/step | O(1) | O(ℓ·d) | O(1) | ℓ·d× better than ProtoGalaxy |
| Total CRC (N steps) | O(√N) | O(N) | O(N) | √N× better |
| Verifier Field Ops | O(log ℓ) | O(ℓ·d) | O(1) | Sublinear in ℓ |
| Prover Time (code) | O(n) | O(n log n) | O(n) | Optimal |
| Post-Quantum | Yes (code) | No | No | New capability |

## Complete Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                  QUASAR SYSTEM ARCHITECTURE                              │
│                                                                                          │
│  ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                          LAYER 5: APPLICATION LAYER                                 │ │
│  │                                                                                     │ │
│  │  ┌─────────────────────────────────────────────────────────────────────────────┐  │ │
│  │  │                        Multi-Instance IVC                                    │  │ │
│  │  │                                                                              │  │ │
│  │  │  Input: z₀, zᵢ, {wₖ}ₖ∈[ℓ], zᵢ₊₁, accᵢ                                      │  │ │
│  │  │  Output: accᵢ₊₁, Πᵢ₊₁                                                       │  │ │
│  │  │                                                                              │  │ │
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │  │ │
│  │  │  │   IVC.P      │  │   IVC.V      │  │   Decider    │  │  Predicate   │  │  │ │
│  │  │  │   (Prover)   │  │  (Verifier)  │  │              │  │  φ(z,w)=1    │  │  │ │
│  │  │  │              │  │              │  │              │  │              │  │  │ │
│  │  │  │ • Arithmetize│  │ • Extract    │  │ • Verify all │  │ • Constraint │  │  │ │
│  │  │  │   predicates │  │   acc.x      │  │   eval claims│  │   checking   │  │  │ │
│  │  │  │ • Generate   │  │ • Verify     │  │ • Check      │  │ • State      │  │  │ │
│  │  │  │   NARK proof │  │   ACC.V      │  │   constraint │  │   transition │  │  │ │
│  │  │  │ • Call ACC.P │  │ • Accept/    │  │ • Verify     │  │              │  │  │ │
│  │  │  │              │  │   Reject     │  │   partial    │  │              │  │  │ │
│  │  │  │              │  │              │  │   eval       │  │              │  │  │ │
│  │  │  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │  │ │
│  │  │                                                                              │  │ │
│  │  └──────────────────────────────────────────────────────────────────────────────┘  │ │
│  └─────────────────────────────────────────────────────────────────────────────────────┘ │
│                                            ↓                                              │
│  ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                     LAYER 4: MULTI-INSTANCE ACCUMULATION LAYER                     │ │
│  │                                                                                     │ │
│  │  ┌─────────────────────────────────────────────────────────────────────────────┐  │ │
│  │  │                   Multi-Instance Accumulation Scheme                         │  │ │
│  │  │                                                                              │  │ │
│  │  │  Input: {xₖ}ₖ∈[ℓ], π_nark, acc                                             │  │ │
│  │  │  Output: acc', π_acc                                                         │  │ │
│  │  │                                                                              │  │ │
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                     │  │ │
│  │  │  │   ACC.P      │  │   ACC.V      │  │   ACC.D      │                     │  │ │
│  │  │  │   (Prover)   │  │  (Verifier)  │  │  (Decider)   │                     │  │ │
│  │  │  │              │  │              │  │              │                     │  │ │
│  │  │  │ • Multi-cast │  │ • Verify     │  │ • Verify all │                     │  │ │
│  │  │  │   reduction  │  │   multi-cast │  │   PCS claims │                     │  │ │
│  │  │  │ • 2-to-1     │  │ • Verify     │  │ • Check      │                     │  │ │
│  │  │  │   folding    │  │   2-to-1     │  │   constraint │                     │  │ │
│  │  │  │ • Combine    │  │ • O(log ℓ)   │  │ • Verify     │                     │  │ │
│  │  │  │   with old   │  │   field ops  │  │   partial    │                     │  │ │
│  │  │  │   accumulator│  │ • O(1) CRC   │  │   eval       │                     │  │ │
│  │  │  │              │  │   ops        │  │              │                     │  │ │
│  │  │  └──────────────┘  └──────────────┘  └──────────────┘                     │  │ │
│  │  │                                                                              │  │ │
│  │  └──────────────────────────────────────────────────────────────────────────────┘  │ │
│  └─────────────────────────────────────────────────────────────────────────────────────┘ │
│                                            ↓                                              │
│  ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                        LAYER 3: REDUCTION LAYER                                     │ │
│  │                                                                                     │ │
│  │  ┌───────────────────────────────────────┐  ┌───────────────────────────────────┐ │ │
│  │  │     Multi-Cast Reduction              │  │     2-to-1 Reduction              │ │ │
│  │  │     NIR_multicast                     │  │     NIR_fold                      │ │ │
│  │  │                                       │  │                                   │ │ │
│  │  │  R^ℓ → R_acc                         │  │  (R_acc)² → R_acc                │ │ │
│  │  │                                       │  │                                   │ │ │
│  │  │  ┌─────────────────────────────────┐ │  │  ┌─────────────────────────────┐ │ │ │
│  │  │  │ 1. Union Polynomial             │ │  │  │ 1. Batch Polynomials        │ │ │ │
│  │  │  │    w̃_∪(Y,X) = Σ eq̃ₖ(Y)·w̃ₖ(X)  │ │  │  │    x̃(Z) = Σ eq̃ₖ(Z)·xₖ     │ │ │ │
│  │  │  │                                 │ │  │  │                             │ │ │ │
│  │  │  │ 2. Commit C_∪                   │ │  │  │ 2. Combine Constraints      │ │ │ │
│  │  │  │                                 │ │  │  │    G(Z) = eq̃(rz,Z)·(...)   │ │ │ │
│  │  │  │ 3. Challenge τ                  │ │  │  │                             │ │ │ │
│  │  │  │                                 │ │  │  │ 3. Sum-Check Protocol       │ │ │ │
│  │  │  │ 4. Partial Eval                 │ │  │  │    Σ G(z) = 0              │ │ │ │
│  │  │  │    w̃(X) = w̃_∪(τ,X)            │ │  │  │                             │ │ │ │
│  │  │  │                                 │ │  │  │ 4. Challenge σ              │ │ │ │
│  │  │  │ 5. Commit C                     │ │  │  │                             │ │ │ │
│  │  │  │                                 │ │  │  │ 5. Oracle Batching (2μ)     │ │ │ │
│  │  │  │ 6. Sum-Check for Constraint     │ │  │  │    Batch m̃_∪,i, m̃_i       │ │ │ │
│  │  │  │    Σ F(x̃(Y),w̃(Y))·eq̃(Y,ry)=0 │ │  │  │                             │ │ │ │
│  │  │  │                                 │ │  │  │ 6. New Accumulator          │ │ │ │
│  │  │  │ 7. Verify w̃_∪(τ,rx) = w̃(rx)   │ │  │  │    acc = (x,τ,rx,rF,e,...)  │ │ │ │
│  │  │  └─────────────────────────────────┘ │  │  └─────────────────────────────┘ │ │ │
│  │  │                                       │  │                                   │ │ │
│  │  │  Complexity:                          │  │  Complexity:                      │ │ │
│  │  │  • Prover: O(ℓ·n) field ops          │  │  • Prover: O(μ·n) field ops      │ │ │
│  │  │  • Verifier: O(log ℓ) field ops      │  │  • Verifier: O(μ) field ops      │ │ │
│  │  │  • Proof: O(log ℓ) elements          │  │  • Proof: O(μ) elements          │ │ │
│  │  └───────────────────────────────────────┘  └───────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────────────────────────────┘ │
│                                            ↓                                              │
│  ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                   LAYER 2: POLYNOMIAL COMMITMENT LAYER                              │ │
│  │                                                                                     │ │
│  │  ┌───────────────────────────────────────┐  ┌───────────────────────────────────┐ │ │
│  │  │     Curve-Based PCS                   │  │     Code-Based PCS                │ │ │
│  │  │     (Mercury, Bulletproofs)           │  │     (Brakedown, Orion, BaseFold)  │ │ │
│  │  │                                       │  │                                   │ │ │
│  │  │  ┌─────────────────────────────────┐ │  │  ┌─────────────────────────────┐ │ │ │
│  │  │  │ Commitment                      │ │  │  │ Commitment                  │ │ │ │
│  │  │  │  C = Commit(f̃)                 │ │  │  │  u = C(f) via linear code  │ │ │ │
│  │  │  │  • Pedersen: C = Σ fᵢ·Gᵢ       │ │  │  │  • Systematic encoding     │ │ │ │
│  │  │  │  • Mercury: Constant size      │ │  │  │  • Merkle root commitment  │ │ │ │
│  │  │  └─────────────────────────────────┘ │  │  └─────────────────────────────┘ │ │ │
│  │  │                                       │  │                                   │ │ │
│  │  │  ┌─────────────────────────────────┐ │  │  ┌─────────────────────────────┐ │ │ │
│  │  │  │ Opening                         │ │  │  │ Opening                     │ │ │ │
│  │  │  │  Prove f̃(x) = v                │ │  │  │  Prove f̃(x) = v            │ │ │ │
│  │  │  │  • IPA-style folding           │ │  │  │  • Proximity testing       │ │ │ │
│  │  │  │  • O(log n) proof size         │ │  │  │  • Out-of-domain sampling  │ │ │ │
│  │  │  └─────────────────────────────────┘ │  │  └─────────────────────────────┘ │ │ │
│  │  │                                       │  │                                   │ │ │
│  │  │  ┌─────────────────────────────────┐ │  │  ┌─────────────────────────────┐ │ │ │
│  │  │  │ Oracle Batching                 │ │  │  │ Oracle Batching             │ │ │ │
│  │  │  │  C = eq̃₀(r)·C₀ + eq̃₁(r)·C₁    │ │  │  │  u = eq̃₀(r)·u₀ + eq̃₁(r)·u₁│ │ │ │
│  │  │  │  • Homomorphic property        │ │  │  │  • Codeword batching       │ │ │ │
│  │  │  │  • O(1) proof size             │ │  │  │  • Proximity test on u     │ │ │ │
│  │  │  │  • O(1) group ops              │ │  │  │  • O(λ/log(1/ρ)·log n) RO │ │ │ │
│  │  │  └─────────────────────────────────┘ │  │  └─────────────────────────────┘ │ │ │
│  │  │                                       │  │                                   │ │ │
│  │  │  Properties:                          │  │  Properties:                      │ │ │
│  │  │  • Fast verification                  │  │  • Linear-time encoding          │ │ │
│  │  │  • Constant proof size (Mercury)      │  │  • Post-quantum secure           │ │ │
│  │  │  • Requires trusted setup (some)      │  │  • Transparent setup             │ │ │
│  │  │  • Classical security only            │  │  • Larger proof size             │ │ │
│  │  └───────────────────────────────────────┘  └───────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────────────────────────────┘ │
│                                            ↓                                              │
│  ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                        LAYER 1: FOUNDATION LAYER                                    │ │
│  │                                                                                     │ │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  ┌───────────┐ │ │
│  │  │   Sum-Check      │  │   Multilinear    │  │  Fiat-Shamir     │  │  Field    │ │ │
│  │  │   Protocol       │  │   Extensions     │  │  Transform       │  │  Arithmetic│ │ │
│  │  │                  │  │                  │  │                  │  │           │ │ │
│  │  │ • Prover         │  │ • MLE(f)         │  │ • Hash-based     │  │ • Add/Mul │ │ │
│  │  │ • Verifier       │  │ • eq̃(X,Y)        │  │   challenges     │  │ • Inv/Neg │ │ │
│  │  │ • Round poly     │  │ • Evaluation     │  │ • ROM security   │  │ • Batch   │ │ │
│  │  │ • O(log n) rnds  │  │ • Partial eval   │  │ • Domain sep     │  │ • SIMD    │ │ │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘  └───────────┘ │ │
│  └─────────────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```


## Detailed Component Analysis

### LAYER 1: Foundation Layer - Building Blocks

#### 1.1 Field Arithmetic Module

**Purpose:** Provides efficient field operations for all higher layers.

**Supported Fields:**
```
┌─────────────────────────────────────────────────────────────┐
│                    Field Implementations                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────┐ │
│  │  Goldilocks      │  │  M61 Field       │  │  BN254    │ │
│  │  q = 2⁶⁴-2³²+1   │  │  q = 2⁶¹-1       │  │  Scalar   │ │
│  │                  │  │                  │  │  Field    │ │
│  │  • 64-bit native │  │  • Mersenne      │  │  • 254-bit│ │
│  │  • Fast NTT      │  │  • Fast mod      │  │  • Pairing│ │
│  │  • Extension F²  │  │  • Extension F²  │  │  • Curve  │ │
│  └──────────────────┘  └──────────────────┘  └───────────┘ │
│                                                              │
│  Operations:                                                 │
│  • Addition: (a + b) mod q                                  │
│  • Multiplication: (a · b) mod q                            │
│  • Inversion: a⁻¹ mod q (Extended Euclidean)               │
│  • Batch operations: SIMD vectorization                     │
│  • Montgomery form: for efficient multiplication            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Key Algorithms:**
1. **Montgomery Multiplication:** O(1) per operation
2. **Batch Inversion:** O(n) for n inversions using product tree
3. **SIMD Operations:** 8× speedup with AVX-512

#### 1.2 Multilinear Extension (MLE) Module

**Purpose:** Convert vectors to multilinear polynomials and perform evaluations.

**MLE Construction:**
```
Input: Vector f ∈ F^n where n = 2^log n
Output: Multilinear polynomial f̃: F^log n → F

Construction:
f̃(X) = Σ_{i∈[n]} f[i] · eq̃(X, Bits(i))

where eq̃(X,Y) = ∏_{j=0}^{log n-1} (Xⱼ·Yⱼ + (1-Xⱼ)·(1-Yⱼ))

Properties:
• f̃(Bits(i)) = f[i] for all i ∈ [n]
• Unique multilinear polynomial with this property
• Degree 1 in each variable
```

**Evaluation Algorithm:**
```
┌─────────────────────────────────────────────────────────────┐
│              MLE Evaluation: f̃(r) for r ∈ F^log n          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Method 1: Direct Evaluation (O(n) time)                    │
│  ─────────────────────────────────────────                  │
│  result = 0                                                  │
│  for i in 0..n:                                             │
│      eq_val = 1                                             │
│      for j in 0..log n:                                     │
│          bit = (i >> j) & 1                                 │
│          if bit == 1:                                       │
│              eq_val *= r[j]                                 │
│          else:                                              │
│              eq_val *= (1 - r[j])                           │
│      result += f[i] * eq_val                                │
│  return result                                              │
│                                                              │
│  Method 2: Recursive Evaluation (O(n) time, cache-friendly) │
│  ──────────────────────────────────────────────────────────  │
│  function eval(f, r, depth):                                │
│      if depth == log n:                                     │
│          return f[0]                                        │
│      n_half = len(f) / 2                                    │
│      f_0 = f[0:n_half]                                      │
│      f_1 = f[n_half:n]                                      │
│      v_0 = eval(f_0, r, depth+1)                            │
│      v_1 = eval(f_1, r, depth+1)                            │
│      return (1 - r[depth]) * v_0 + r[depth] * v_1           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Partial Evaluation:**
```
Input: f̃(Y,X) where Y ∈ F^log ℓ, X ∈ F^log n
       Point τ ∈ F^log ℓ
Output: g̃(X) = f̃(τ,X)

Algorithm:
1. Fix Y = τ in f̃(Y,X)
2. Result is a polynomial in X only
3. Complexity: O(ℓ·n) field operations

Example:
f̃(Y,X) = Y₀·X₀ + Y₁·X₁ + Y₀·Y₁·X₀·X₁
τ = (τ₀, τ₁)
g̃(X) = τ₀·X₀ + τ₁·X₁ + τ₀·τ₁·X₀·X₁
```

#### 1.3 Sum-Check Protocol Module

**Purpose:** Verify polynomial sums over Boolean hypercube with logarithmic communication.

**Protocol Flow:**
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Sum-Check Protocol for Σ_{x∈B^ℓ} g(x) = v               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Round 1:                                                                    │
│  ────────                                                                    │
│  Prover:                                                                     │
│    Compute g₁(X₀) = Σ_{x₁,...,x_{ℓ-1}∈B^{ℓ-1}} g(X₀, x₁, ..., x_{ℓ-1})   │
│    Send g₁(X₀) as univariate polynomial of degree d                         │
│                                                                              │
│  Verifier:                                                                   │
│    Check: g₁(0) + g₁(1) = v                                                 │
│    Sample: r₀ ←$ F                                                          │
│    Send: r₀                                                                  │
│                                                                              │
│  Round i (2 ≤ i ≤ ℓ):                                                       │
│  ────────────────────                                                        │
│  Prover:                                                                     │
│    Compute gᵢ(Xᵢ₋₁) = Σ_{xᵢ,...,x_{ℓ-1}∈B^{ℓ-i}} g(r₀,...,rᵢ₋₂,Xᵢ₋₁,xᵢ,...) │
│    Send gᵢ(Xᵢ₋₁)                                                            │
│                                                                              │
│  Verifier:                                                                   │
│    Check: gᵢ(0) + gᵢ(1) = gᵢ₋₁(rᵢ₋₂)                                        │
│    Sample: rᵢ₋₁ ←$ F                                                        │
│    Send: rᵢ₋₁                                                               │
│                                                                              │
│  Final Round:                                                                │
│  ────────────                                                                │
│  Verifier:                                                                   │
│    Check: g_ℓ(r_{ℓ-1}) = g(r₀, r₁, ..., r_{ℓ-1})                           │
│    Query oracle for g(r₀, ..., r_{ℓ-1})                                    │
│                                                                              │
│  Complexity:                                                                 │
│  • Rounds: ℓ                                                                │
│  • Communication: ℓ·(d+1) field elements                                    │
│  • Prover time: O(2^ℓ) field operations                                     │
│  • Verifier time: O(ℓ·d) field operations                                   │
│  • Soundness error: ℓ·d / |F|                                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Optimization - Dynamic Programming:**
```
For polynomial g(X) = Σᵢ cᵢ·∏ⱼ Xⱼ^{eᵢⱼ}

Precompute intermediate sums:
S[i][r₀,...,rᵢ₋₁] = Σ_{xᵢ,...,x_{ℓ-1}∈B^{ℓ-i}} g(r₀,...,rᵢ₋₁,xᵢ,...)

Update rule:
S[i+1][r₀,...,rᵢ] = (1-rᵢ)·S[i][r₀,...,rᵢ₋₁,0] + rᵢ·S[i][r₀,...,rᵢ₋₁,1]

This reduces prover time from O(2^ℓ·ℓ) to O(2^ℓ)
```

#### 1.4 Fiat-Shamir Transform Module

**Purpose:** Convert interactive protocols to non-interactive using hash functions.

**Transformation Process:**
```
┌─────────────────────────────────────────────────────────────┐
│              Fiat-Shamir Transformation                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Interactive Protocol:                                       │
│  ────────────────────                                        │
│  P → V: m₁                                                   │
│  V → P: r₁ ←$ F                                             │
│  P → V: m₂                                                   │
│  V → P: r₂ ←$ F                                             │
│  ...                                                         │
│                                                              │
│  Non-Interactive (Fiat-Shamir):                             │
│  ──────────────────────────────                             │
│  P computes:                                                 │
│    m₁                                                        │
│    r₁ = H(transcript || m₁)                                 │
│    m₂                                                        │
│    r₂ = H(transcript || m₁ || r₁ || m₂)                    │
│    ...                                                       │
│  P sends: (m₁, m₂, ...)                                     │
│                                                              │
│  V verifies:                                                 │
│    r₁ = H(transcript || m₁)                                 │
│    r₂ = H(transcript || m₁ || r₁ || m₂)                    │
│    ...                                                       │
│    Check protocol verification                              │
│                                                              │
│  Security:                                                   │
│  • Random Oracle Model (ROM)                                │
│  • Hash function H: {0,1}* → F                              │
│  • Domain separation for different phases                   │
│  • Collision resistance required                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Hash Function Requirements:**
- **Collision Resistance:** Finding H(x) = H(y) with x ≠ y is hard
- **Output Length:** At least 2λ bits for λ-bit security
- **Recommended:** SHA-3, BLAKE3, or BLAKE2b
- **Domain Separation:** Include protocol phase identifier in hash input

### LAYER 2: Polynomial Commitment Layer

#### 2.1 Curve-Based PCS (Mercury/Bulletproofs)

**Architecture:**
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Curve-Based PCS Architecture                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Setup Phase:                                                                │
│  ───────────                                                                 │
│  • Generate structured reference string (SRS)                                │
│  • G₀, G₁, ..., G_{n-1} ∈ G (group elements)                                │
│  • For Mercury: Additional structure for constant proofs                     │
│                                                                              │
│  Commitment Phase:                                                           │
│  ────────────────                                                            │
│  Input: f̃(X) = Σᵢ fᵢ·Lᵢ(X) (multilinear polynomial)                        │
│  Output: C ∈ G                                                               │
│                                                                              │
│  C = Σᵢ fᵢ·Gᵢ                                                               │
│                                                                              │
│  Properties:                                                                 │
│  • Homomorphic: C(f+g) = C(f) + C(g)                                        │
│  • Binding: Computationally hard to find f ≠ g with C(f) = C(g)            │
│  • Hiding: C reveals no information about f (with blinding)                 │
│                                                                              │
│  Opening Phase:                                                              │
│  ─────────────                                                               │
│  Input: f̃, point x ∈ F^log n, claimed value v                              │
│  Output: Proof π                                                             │
│                                                                              │
│  Bulletproofs approach:                                                      │
│  1. Recursive halving of polynomial                                          │
│  2. Send L, R commitments at each step                                       │
│  3. Final opening at single point                                            │
│  4. Proof size: O(log n) group elements                                      │
│                                                                              │
│  Mercury approach:                                                           │
│  1. Structured commitment with tensor product                                │
│  2. Constant-size proof using special structure                              │
│  3. No prover FFTs required                                                  │
│  4. Proof size: O(1) group elements                                          │
│                                                                              │
│  Verification:                                                               │
│  ────────────                                                                │
│  • Check commitment equation                                                 │
│  • Verify recursive structure                                                │
│  • Time: O(log n) for Bulletproofs, O(1) for Mercury                        │
│                                                                              │
│  Oracle Batching:                                                            │
│  ───────────────                                                             │
│  Input: C₀, C₁, challenge r                                                  │
│  Output: C = eq̃₀(r)·C₀ + eq̃₁(r)·C₁                                         │
│                                                                              │
│  • Homomorphic property enables trivial batching                             │
│  • No additional proof needed                                                │
│  • Verification: O(1) group operations                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Complexity Analysis:**
```
Operation          | Bulletproofs | Mercury
─────────────────────────────────────────────
Commitment         | O(n log n)   | O(n log n)
Opening Proof      | O(n log n)   | O(n)
Proof Size         | O(log n)     | O(1)
Verification       | O(log n)     | O(1)
Batching Proof     | O(1)         | O(1)
Batching Verify    | O(1)         | O(1)
```
