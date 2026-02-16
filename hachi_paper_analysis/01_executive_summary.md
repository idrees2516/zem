# Hachi Paper - Executive Summary

## Paper Title
**Hachi: Efficient Lattice-Based Multilinear Polynomial Commitments over Extension Fields**

## Authors
- Ngoc Khanh Nguyen (King's College London)
- George O'Rourke (King's College London)
- Jiapeng Zhang (University of Southern California)

## Core Innovation
Hachi presents a lattice-based multilinear polynomial commitment scheme that achieves:
- **Succinct proof sizes**: poly(ℓ, λ) where ℓ is number of variables, λ is security parameter
- **Square-root verifier time**: Õ(√(2^ℓ) · λ) operations
- **12.5× faster verification** compared to Greyhound (state-of-the-art)
- **Compact proofs**: ~55 KB

## Key Technical Contributions

### 1. Ring Switching Integration
- Combines Greyhound framework with ring-switching technique from Huang, Mao, Zhang (2025)
- Lifts statements from R_q to polynomial ring F_{q^k}[X]
- Enables sumcheck protocol over extension fields instead of cyclotomic rings
- **Critical insight**: Verifier performs NO cyclotomic ring operations

### 2. Generic Field Extension Reduction
- Transforms ℓ-variate polynomial evaluations over F_{q^k}
- Reduces to (ℓ - α + κ)-variate evaluations over R_q
- Where d = 2^α (ring dimension) and k = 2^κ (extension degree)
- Generalizes SLAP results in two directions:
  - Supports field extensions (not just prime fields)
  - Extends from univariate to multivariate case

### 3. Flexible Ring Dimension Selection
- Unlike Greyhound/LaBRADOR, not constrained to small ring dimensions
- Larger d enables:
  - Faster commitment via optimized NTT-based multiplication
  - Sparse challenge space for efficient folding
- Sumcheck over extension field independent of d size

## Performance Comparison

| Scheme | Multilinear | Extension Fields | Proof Size | Verifier Time | Concrete Proof | Concrete Verify |
|--------|-------------|------------------|------------|---------------|----------------|-----------------|
| Greyhound | ✗ | ✗ | poly(ℓ,λ) | Õ(λ·√(2^ℓ)·λ) | 53KB | 2.8s |
| Hachi | ✓ | ✓ | poly(ℓ,λ) | Õ(√(2^ℓ)·λ) | 55KB | 227ms |

*Concrete numbers for ℓ=30 variables*

## Security Foundation
- Based on Module-SIS assumption (standard lattice assumption)
- Random Oracle Model for Fiat-Shamir transformation
- Achieves λ=128 bit security level
- Post-quantum secure

## Implementation Status
- Prototype implementation in Rust
- Early stage but demonstrates advantages:
  - 10× faster verification than Greyhound
  - 3-5× faster commitment time
  - Amenable to SIMD optimizations

## Target Applications
- Succinct Non-Interactive Arguments of Knowledge (SNARKs)
- Lookup arguments
- Multi-party computation
- Post-quantum cryptographic systems
- Zero-knowledge virtual machines (zkVMs)
