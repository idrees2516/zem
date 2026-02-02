# Hachi: Complete Design Document
## Comprehensive Architecture and Implementation Specification

**Document Purpose:** This document provides a complete design for implementing Hachi within the neo-lattice-zkvm codebase, mapping every requirement from the paper to specific modules, data structures, and algorithms.

**Status:** Design Phase - Ready for Implementation
**Target:** Production-ready implementation with 12.5× verification speedup over Greyhound

---

## TABLE OF CONTENTS

### PART I: ARCHITECTURE OVERVIEW
1. System Architecture
2. Module Dependencies
3. Integration Points
4. Data Flow

### PART II: CORE MATHEMATICAL PRIMITIVES
5. Extension Field Implementation
6. Cyclotomic Ring Extensions
7. Galois Automorphisms
8. Trace Map Implementation

### PART III: COMMITMENT SCHEME DESIGN
9. Inner-Outer Commitment Structure
10. Weak Opening Protocol
11. Binding Security

### PART IV: RING SWITCHING PROTOCOL
12. Polynomial Lifting
13. Multilinear Extension Commitment
14. Challenge Substitution

### PART V: SUMCHECK INTEGRATION
15. Extension Field Sumcheck
16. Round Protocol
17. Evaluation Proof

### PART VI: NORM VERIFICATION
18. Range Proof Framework
19. Zero-Coefficient Verification
20. Coordinate-Wise Soundness

### PART VII: COMPLETE PROTOCOL
21. Setup Phase
22. Commitment Phase
23. Evaluation Proof Phase
24. Verification Phase

### PART VIII: OPTIMIZATION STRATEGIES
25. SIMD Vectorization
26. Parallel Execution
27. Memory Management
28. Caching Strategies

### PART IX: TESTING AND VALIDATION
29. Unit Tests
30. Integration Tests
31. Performance Benchmarks
32. Security Validation

---


# PART I: ARCHITECTURE OVERVIEW

## 1. System Architecture

### 1.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HACHI POLYNOMIAL COMMITMENT               │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Setup      │  │  Commitment  │  │  Evaluation  │          │
│  │   Phase      │──│    Phase     │──│    Proof     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                  │                  │                  │
│         ▼                  ▼                  ▼                  │
│  ┌──────────────────────────────────────────────────┐          │
│  │         RING SWITCHING LAYER                      │          │
│  │  • Polynomial Lifting: R_q → Z_q[X]              │          │
│  │  • Extension Field Evaluation: X = α ∈ F_{q^k}   │          │
│  │  • Multilinear Extension: mle[(z', r')]          │          │
│  └──────────────────────────────────────────────────┘          │
│         │                  │                  │                  │
│         ▼                  ▼                  ▼                  │
│  ┌──────────────────────────────────────────────────┐          │
│  │         SUMCHECK PROTOCOL LAYER                   │          │
│  │  • Extension Field Sumcheck over F_{q^k}         │          │
│  │  • Round-by-Round Prover/Verifier                │          │
│  │  • Evaluation Claim Reduction                    │          │
│  └──────────────────────────────────────────────────┘          │
│         │                  │                  │                  │
│         ▼                  ▼                  ▼                  │
│  ┌──────────────────────────────────────────────────┐          │
│  │         COMMITMENT SCHEME LAYER                   │          │
│  │  • Inner-Outer Ajtai Commitment                  │          │
│  │  • Weak Opening Protocol                         │          │
│  │  • Module-SIS Binding                            │          │
│  └──────────────────────────────────────────────────┘          │
│         │                  │                  │                  │
│         ▼                  ▼                  ▼                  │
│  ┌──────────────────────────────────────────────────┐          │
│  │         MATHEMATICAL PRIMITIVES LAYER             │          │
│  │  • Extension Fields F_{q^k}                      │          │
│  │  • Cyclotomic Rings R_q                          │          │
│  │  • Galois Automorphisms σ_i                      │          │
│  │  • Trace Maps Tr_H                               │          │
│  └──────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Module Structure

```
neo-lattice-zkvm/src/hachi/
├── mod.rs                          # Main module exports
├── types.rs                        # Core type definitions
├── params.rs                       # Parameter selection
├── errors.rs                       # Error types
│
├── primitives/                     # Mathematical primitives
│   ├── mod.rs
│   ├── extension_field.rs          # F_{q^k} implementation
│   ├── ring_fixed_subgroup.rs      # R_q^H subfield
│   ├── galois_automorphisms.rs     # σ_i operations
│   ├── trace_map.rs                # Tr_H implementation
│   ├── inner_product.rs            # ψ bijection (Theorem 2)
│   └── norm_preservation.rs        # Lemma 6 implementation
│
├── embedding/                      # Extension field embedding
│   ├── mod.rs
│   ├── generic_transform.rs        # F_{q^k} → R_q (Section 3.1)
│   ├── optimized_fq.rs             # F_q polynomial case (Section 3.2)
│   ├── quadratic_reduction.rs      # Multilinear → quadratic
│   └── gadget_decomposition.rs     # G_n^{-1} operations
│
├── commitment/                     # Commitment scheme
│   ├── mod.rs
│   ├── inner_outer.rs              # Inner-outer structure (Figure 3)
│   ├── weak_opening.rs             # Weak opening protocol
│   ├── binding.rs                  # Lemma 7 implementation
│   └── homomorphic.rs              # Homomorphic operations
│
├── ring_switching/                 # Ring switching protocol
│   ├── mod.rs
│   ├── polynomial_lifting.rs       # R_q → Z_q[X] (Section 4.1)
│   ├── mle_commitment.rs           # mle[(z', r')] commitment
│   ├── challenge_substitution.rs   # X = α evaluation
│   └── inner_product_reduction.rs  # Inner product claims
│
├── sumcheck/                       # Sumcheck protocol
│   ├── mod.rs
│   ├── extension_field_prover.rs   # Prover over F_{q^k}
│   ├── extension_field_verifier.rs # Verifier over F_{q^k}
│   ├── round_protocol.rs           # Round-by-round execution
│   ├── evaluation_proof.rs         # Final evaluation (Lemma 9)
│   └── batching.rs                 # Batch multiple sumchecks
│
├── norm_verification/              # Norm verification
│   ├── mod.rs
│   ├── range_proof.rs              # Range proofs over F_{q^k}
│   ├── zero_coefficient.rs         # Zero-coeff check (Lemma 10)
│   └── coordinate_wise.rs          # CWSS implementation
│
├── protocol/                       # Complete protocol
│   ├── mod.rs
│   ├── setup.rs                    # Setup algorithm
│   ├── commit.rs                   # Commitment algorithm
│   ├── prove.rs                    # Evaluation proof algorithm
│   ├── verify.rs                   # Verification algorithm
│   └── recursive.rs                # Recursive structure
│
├── optimization/                   # Performance optimizations
│   ├── mod.rs
│   ├── simd.rs                     # SIMD vectorization
│   ├── parallel.rs                 # Parallel execution
│   ├── memory.rs                   # Memory management
│   └── cache.rs                    # Caching strategies
│
└── tests/                          # Comprehensive tests
    ├── mod.rs
    ├── unit_tests.rs
    ├── integration_tests.rs
    ├── performance_tests.rs
    └── security_tests.rs
```

### 1.3 Existing Module Integration

**Leverage Existing Modules:**

```rust
// From neo-lattice-zkvm/src/ring/
use crate::ring::{
    CyclotomicRing,           // Base cyclotomic ring R_q
    RingElement,              // Ring element representation
    ntt::NTT,                 // NTT for fast multiplication
    decomposition,            // Gadget decomposition
};

// From neo-lattice-zkvm/src/field/
use crate::field::{
    Field,                    // Base field trait
    GoldilocksField,          // Goldilocks field F_q
    ExtensionField,           // Extension field F_{q^2}
    extension_framework,      // General F_{q^k} framework
};

// From neo-lattice-zkvm/src/commitment/
use crate::commitment::{
    ajtai::AjtaiCommitment,   // Base Ajtai commitment
    matrix::MatrixCommitment, // Matrix commitment utilities
};

// From neo-lattice-zkvm/src/sumcheck/
use crate::sumcheck::{
    MultilinearPolynomial,    // MLE representation
    DenseSumCheckProver,      // Dense sumcheck prover
    DenseSumCheckVerifier,    // Dense sumcheck verifier
};

// From neo-lattice-zkvm/src/polynomial/
use crate::polynomial::{
    multilinear::MultilinearExtension,
};

// From neo-lattice-zkvm/src/fiat_shamir/
use crate::fiat_shamir::{
    hash_oracle::HashOracle,  // Fiat-Shamir transformation
    transform::FiatShamirTransform,
};
```

### 1.4 New Module Requirements

**Modules to Implement:**

1. **Extension Field Arithmetic (F_{q^k})**
   - Extend existing `ExtensionField<F>` to support k = 2^κ
   - Implement efficient arithmetic for k ∈ {2, 4, 8, 16}
   - SIMD-optimized operations

2. **Ring Fixed Subgroup (R_q^H)**
   - Implement H := ⟨σ_{-1}, σ_{4k+1}⟩
   - Fixed ring R_q^H ≅ F_{q^k}
   - Element structure (Equation 7)

3. **Bijective Packing (ψ)**
   - Implement ψ : (R_q^H)^{d/k} → R_q (Theorem 2)
   - Inverse ψ^{-1} for extraction
   - Inner product preservation

4. **Trace Map (Tr_H)**
   - Efficient trace computation
   - Cached automorphism applications
   - Batch trace operations

5. **Ring Switching**
   - Polynomial lifting R_q → Z_q[X]
   - Challenge substitution X = α
   - Coefficient extraction

6. **Extension Field Sumcheck**
   - Sumcheck prover over F_{q^k}
   - Sumcheck verifier over F_{q^k}
   - No cyclotomic ring operations in verifier!

---

## 2. Module Dependencies

### 2.1 Dependency Graph

```
┌─────────────────────────────────────────────────────────────┐
│                     Dependency Layers                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Layer 5: Protocol                                           │
│  ┌──────────────────────────────────────────────┐           │
│  │  hachi::protocol::{setup, commit, prove}     │           │
│  └──────────────────────────────────────────────┘           │
│                        │                                      │
│                        ▼                                      │
│  Layer 4: High-Level Components                              │
│  ┌──────────────────────────────────────────────┐           │
│  │  hachi::ring_switching                        │           │
│  │  hachi::sumcheck                              │           │
│  │  hachi::norm_verification                     │           │
│  └──────────────────────────────────────────────┘           │
│                        │                                      │
│                        ▼                                      │
│  Layer 3: Embedding & Commitment                             │
│  ┌──────────────────────────────────────────────┐           │
│  │  hachi::embedding                             │           │
│  │  hachi::commitment                            │           │
│  └──────────────────────────────────────────────┘           │
│                        │                                      │
│                        ▼                                      │
│  Layer 2: Mathematical Primitives                            │
│  ┌──────────────────────────────────────────────┐           │
│  │  hachi::primitives::{extension_field,        │           │
│  │    ring_fixed_subgroup, galois, trace}       │           │
│  └──────────────────────────────────────────────┘           │
│                        │                                      │
│                        ▼                                      │
│  Layer 1: Base Infrastructure (Existing)                     │
│  ┌──────────────────────────────────────────────┐           │
│  │  ring::{CyclotomicRing, RingElement, NTT}   │           │
│  │  field::{Field, GoldilocksField, Extension} │           │
│  │  commitment::ajtai                            │           │
│  │  sumcheck::{MultilinearPolynomial, Prover}  │           │
│  └──────────────────────────────────────────────┘           │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Critical Dependencies

**Layer 1 → Layer 2:**
- `CyclotomicRing<F>` → `RingFixedSubgroup<F>` (implements R_q^H)
- `Field` → `ExtensionFieldK<F, K>` (implements F_{q^k})
- `RingElement<F>` → `GaloisAutomorphism` (implements σ_i)

**Layer 2 → Layer 3:**
- `RingFixedSubgroup<F>` → `BijectivePacking` (implements ψ)
- `TraceMap` → `InnerProductPreservation` (Theorem 2)
- `ExtensionFieldK<F, K>` → `GenericTransform` (F_{q^k} → R_q)

**Layer 3 → Layer 4:**
- `GenericTransform` → `PolynomialLifting` (embedding to ring switching)
- `InnerOuterCommitment` → `MLECommitment` (commitment to MLE)
- `WeakOpening` → `RingSwitchingProtocol` (opening in ring switching)

**Layer 4 → Layer 5:**
- `RingSwitchingProtocol` → `HachiProver` (ring switching in proof)
- `ExtensionFieldSumcheck` → `HachiVerifier` (sumcheck in verification)
- `NormVerification` → `HachiProver` (norm proofs in proof)

### 2.3 External Dependencies

```toml
[dependencies]
# Existing dependencies
num-complex = "0.4"          # For canonical embedding
rand = "0.8"                 # For randomness
rand_chacha = "0.3"          # For deterministic RNG
sha3 = "0.10"                # For Fiat-Shamir
rayon = "1.7"                # For parallelization

# New dependencies for Hachi
# (None required - use existing infrastructure)
```

---

## 3. Integration Points

### 3.1 Integration with Existing Commitment Schemes

**Greyhound Integration:**
```rust
// Hachi can be used as drop-in replacement for Greyhound
pub trait PolynomialCommitmentScheme {
    type Params;
    type Commitment;
    type Proof;
    
    fn setup(params: Self::Params) -> Self;
    fn commit(&self, polynomial: &MultilinearPolynomial) -> Self::Commitment;
    fn prove_evaluation(&self, point: &[FieldElement], value: FieldElement) -> Self::Proof;
    fn verify(&self, commitment: &Self::Commitment, point: &[FieldElement], 
              value: FieldElement, proof: &Self::Proof) -> bool;
}

// Hachi implements this trait
impl PolynomialCommitmentScheme for HachiPCS {
    // ... implementation
}

// Greyhound also implements this trait
impl PolynomialCommitmentScheme for GreyhoundPCS {
    // ... implementation
}

// Can switch between them:
let pcs: Box<dyn PolynomialCommitmentScheme> = if use_hachi {
    Box::new(HachiPCS::setup(params))
} else {
    Box::new(GreyhoundPCS::setup(params))
};
```

### 3.2 Integration with Folding Schemes

**Neo Integration:**
```rust
// Hachi provides commitment scheme for Neo folding
use crate::neo::folding::NeoFoldingScheme;
use crate::hachi::HachiPCS;

pub struct NeoWithHachi<F: Field> {
    folding: NeoFoldingScheme<F>,
    pcs: HachiPCS<F>,
}

impl<F: Field> NeoWithHachi<F> {
    pub fn fold_instances(&mut self, instances: &[Instance<F>]) -> FoldedInstance<F> {
        // Use Hachi for committing to folded witness
        let folded_witness = self.folding.fold_witnesses(instances);
        let commitment = self.pcs.commit(&folded_witness);
        
        FoldedInstance {
            commitment,
            // ... other fields
        }
    }
}
```

**LatticeFold+ Integration:**
```rust
// Hachi can replace LatticeFold+ commitment scheme
use crate::latticefold_plus::engine::LatticeFoldPlusEngine;
use crate::hachi::HachiPCS;

pub struct LatticeFoldPlusWithHachi<F: Field> {
    engine: LatticeFoldPlusEngine<F>,
    pcs: HachiPCS<F>,
}

// Hachi's faster verification benefits LatticeFold+ significantly
```

### 3.3 Integration with zkVM

**Jolt Integration:**
```rust
// Use Hachi for Jolt zkVM polynomial commitments
use crate::jolt_zkvm::core::JoltVM;
use crate::hachi::HachiPCS;

pub struct JoltWithHachi<F: Field> {
    vm: JoltVM<F>,
    pcs: HachiPCS<F>,
}

impl<F: Field> JoltWithHachi<F> {
    pub fn prove_execution(&self, program: &Program, input: &Input) -> ExecutionProof<F> {
        // Execute program
        let trace = self.vm.execute(program, input);
        
        // Commit to execution trace using Hachi
        let trace_commitment = self.pcs.commit(&trace.to_multilinear());
        
        // Generate proof with 12.5× faster verification
        ExecutionProof {
            trace_commitment,
            // ... other fields
        }
    }
}
```

### 3.4 Integration with SNARK Systems

**Symphony Integration:**
```rust
// Hachi as PCS backend for Symphony SNARK
use crate::snark::symphony::SymphonyProver;
use crate::hachi::HachiPCS;

pub struct SymphonyWithHachi<F: Field> {
    prover: SymphonyProver<F>,
    pcs: HachiPCS<F>,
}

// Symphony benefits from Hachi's fast verification
// Especially important for recursive SNARKs
```

---

## 4. Data Flow

### 4.1 Setup Phase Data Flow

```
Input: Security parameter λ, polynomial degree ℓ
│
├─> 1. Parameter Selection
│   ├─> Ring dimension d = 2^α
│   ├─> Extension degree k = 2^κ (divides d/2)
│   ├─> Prime modulus q ≡ 5 (mod 8)
│   ├─> Module-SIS parameters (κ, n, β_SIS)
│   └─> Norm bounds (B_bnd, B_rbnd)
│
├─> 2. Ring Setup
│   ├─> Initialize CyclotomicRing<F> with degree d
│   ├─> Compute Galois subgroup H = ⟨σ_{-1}, σ_{4k+1}⟩
│   ├─> Precompute primitive roots for canonical embedding
│   └─> Initialize NTT if available
│
├─> 3. Extension Field Setup
│   ├─> Initialize ExtensionFieldK<F, k>
│   ├─> Compute irreducible polynomial φ(Z) of degree k
│   ├─> Precompute Frobenius automorphism powers
│   └─> Setup SIMD operations
│
├─> 4. Commitment Key Generation
│   ├─> Sample matrix A ∈ R_q^{κ×n} uniformly
│   ├─> Compute inner commitment key A_in
│   ├─> Compute outer commitment key A_out
│   └─> Store commitment keys
│
└─> Output: Public parameters pp = (ring, extension_field, commitment_keys)
```

### 4.2 Commitment Phase Data Flow

```
Input: Polynomial f ∈ F_{q^k}^{≤1}[X_1, ..., X_ℓ], public parameters pp
│
├─> 1. Embedding Transform (if needed)
│   ├─> If f over F_{q^k}: Apply generic transform (Section 3.1)
│   │   ├─> Partition variables: outer (ℓ-α+κ), inner (α-κ)
│   │   ├─> Construct ring elements F_i = ψ((f_{i||j})_j)
│   │   └─> Output: F ∈ R_q^{2^{ℓ-α+κ}}
│   │
│   └─> If f over F_q: Apply optimized transform (Section 3.2)
│       ├─> Compute partial evaluations y_i
│       ├─> Construct aggregated polynomial f'
│       └─> Output: F ∈ R_q^{2^{ℓ-α}}
│
├─> 2. Quadratic Reduction
│   ├─> Split variables: μ = m + r
│   ├─> Construct coefficient vectors f_i ∈ R_q^{2^m}
│   ├─> Apply gadget decomposition: s = G_{2^μ}^{-1}(f)
│   └─> Output: Witness s ∈ R_q^{2^m·δ}
│
├─> 3. Inner-Outer Commitment
│   ├─> Split witness: s = (s_1, ..., s_{2^r})
│   ├─> Compute partial commitments: t_i = A_in·s_i
│   ├─> Commit to partial commitments: u = A_out·t
│   └─> Output: Commitment C = u ∈ R_q^{κ_out}
│
└─> Output: Commitment C, witness s (kept secret)
```

### 4.3 Evaluation Proof Data Flow

```
Input: Polynomial f, evaluation point x ∈ F_{q^k}^ℓ, value y, witness s
│
├─> 1. Compute Evaluation Claim
│   ├─> Verify f(x) = y locally
│   ├─> Construct evaluation vectors a, b
│   └─> Formulate quadratic equation: b^T·(a^T ⊗ I)·(g^T ⊗ I)·s = y
│
├─> 2. Ring Switching
│   ├─> Lift to Z_q[X]: Σ_k M_k(X)·z_k(X) = w(X) + (X^d + 1)·r(X)
│   ├─> Extract coefficients: z', r' ∈ Z_q^*
│   ├─> Commit to MLE: P = mle[(z', r')] ∈ F_{q^k}^{≤1}[X_1, ..., X_μ]
│   ├─> Receive challenge: α ← F_{q^k}
│   └─> Substitute: X = α reduces to inner product over F_{q^k}
│
├─> 3. Sumcheck Protocol
│   ├─> Transform to sumcheck: Σ_{i∈{0,1}^μ} P(i)·Q(i) = V
│   ├─> For round j = 1, ..., μ:
│   │   ├─> Prover: Compute g_j(X) = Σ_{b∈{0,1}^{μ-j}} P(r_{<j}, X, b)·Q(r_{<j}, X, b)
│   │   ├─> Prover: Send g_j (univariate polynomial over F_{q^k})
│   │   ├─> Verifier: Check g_j(0) + g_j(1) = previous sum
│   │   └─> Verifier: Send challenge r_j ← F_{q^k}
│   │
│   └─> Final: Prover sends P(r_1, ..., r_μ)
│
├─> 4. Norm Verification
│   ├─> Prove ||z'_i|| ≤ β for all coordinates
│   ├─> Use range proofs over F_{q^k}
│   ├─> Batch multiple range proofs
│   └─> Verify zero-coefficient constraints (Lemma 10)
│
├─> 5. Recursive Evaluation
│   ├─> Reduce to evaluation of P at (r_1, ..., r_μ)
│   ├─> P = mle[(z', r')] has smaller size than f
│   ├─> Recursively apply protocol
│   └─> Base case: Direct evaluation
│
└─> Output: Evaluation proof π
```

### 4.4 Verification Phase Data Flow

```
Input: Commitment C, evaluation point x, value y, proof π, public parameters pp
│
├─> 1. Parse Proof
│   ├─> Extract ring switching components
│   ├─> Extract sumcheck rounds
│   ├─> Extract norm verification proofs
│   └─> Extract recursive evaluation proofs
│
├─> 2. Verify Ring Switching
│   ├─> Check MLE commitment is well-formed
│   ├─> Verify challenge α was properly generated (Fiat-Shamir)
│   └─> Verify substitution X = α is correct
│
├─> 3. Verify Sumcheck Protocol
│   ├─> For round j = 1, ..., μ:
│   │   ├─> Verify g_j(0) + g_j(1) = previous sum
│   │   ├─> Compute challenge r_j (Fiat-Shamir)
│   │   └─> Update running sum
│   │
│   ├─> Verify final evaluation: P(r_1, ..., r_μ)·Q(r_1, ..., r_μ) = g_μ(r_μ)
│   └─> All operations over F_{q^k} (NO cyclotomic ring operations!)
│
├─> 4. Verify Norm Proofs
│   ├─> Verify range proofs for ||z'_i|| ≤ β
│   ├─> Verify zero-coefficient constraints
│   └─> Check coordinate-wise special soundness
│
├─> 5. Verify Recursive Evaluation
│   ├─> Recursively verify evaluation of P
│   ├─> Check consistency with sumcheck final evaluation
│   └─> Verify base case evaluation
│
└─> Output: Accept/Reject
```

### 4.5 Performance Characteristics

**Complexity Analysis:**

| Phase | Prover Time | Verifier Time | Communication |
|-------|-------------|---------------|---------------|
| Setup | O(κ·n·d) | O(1) | O(κ·n·d) |
| Commit | O(2^ℓ·d·log d) | O(1) | O(κ·d) |
| Prove | O(2^ℓ·μ·k) | - | O(μ·k + log(2^ℓ)) |
| Verify | - | Õ(√(2^ℓ)·λ) | - |

**Key Improvements over Greyhound:**
- Verifier: Õ(√(2^ℓ)·λ) vs Õ(λ·√(2^ℓ)·λ) → **Õ(λ) speedup**
- No cyclotomic ring operations in verifier
- All verifier operations over small extension field F_{q^k}

**Concrete Performance (ℓ = 30):**
- Verification: 227ms (Hachi) vs 2.8s (Greyhound) → **12.5× faster**
- Proof size: ~55KB (Hachi) vs ~53KB (Greyhound) → **Comparable**
- Commitment: 3-5× faster (larger ring dimension d)

---

