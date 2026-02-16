# Hachi Paper - Complete Analysis and Requirements

This directory contains a comprehensive, in-depth analysis of the Hachi paper: "Hachi: Efficient Lattice-Based Multilinear Polynomial Commitments over Extension Fields" by Nguyen, O'Rourke, and Zhang.

## Document Structure

### 1. Executive Summary (`01_executive_summary.md`)
- Paper overview and core innovations
- Key technical contributions
- Performance comparison with Greyhound
- Security foundation and target applications

### 2. Mathematical Foundations (`02_mathematical_foundations.md`)
- Complete notation and basic structures
- Ring structures (R, R_q, F_{q^k})
- Norms and bounds
- Gadget matrices and decomposition
- Galois automorphisms and trace maps
- Multilinear extensions
- Hardness assumptions (Module-SIS)
- Invertibility properties
- Norm inequalities

### 3. Field Extension Embedding (`03_field_extension_embedding.md`)
- Subfield identification (Lemma 5)
  - Theorem statement and proof
  - Subgroup structure
  - Fixed element structure
  - Field properties
- Inner product embedding (Theorem 2)
  - Main theorem and bijection property
  - Complete proof with all auxiliary claims
  - Inner product calculation
  - Norm preservation
- Generic transformation (Section 3.1)
  - Problem setup and transformation steps
  - Communication cost analysis
- Optimized transformation for base field (Section 3.2)
  - Special case handling
  - Variable reduction comparison

### 4. Commitment Scheme (`04_commitment_scheme.md`)
- Inner-outer commitment structure
  - Public parameters
  - Decomposition base
  - Witness structure
- Inner commitment (Ajtai-style)
  - Decomposition step
  - Commitment computation
  - Inner commitment decomposition
- Outer commitment
  - Commitment computation
  - Standard and weak openings
- Weak binding property (Lemma 7)
  - Complete proof
  - Parameter requirements
- Polynomial evaluation as quadratic equation
  - Problem setup
  - Split representation
  - Commitment opening relation
  - Intermediate witness
  - Evaluation commitment
- Split-and-fold protocol (Figure 3)
  - Round-by-round description
  - Verification equations
  - Norm bound analysis
- Coordinate-wise special soundness (Lemma 8)
  - Statement and extraction algorithm
  - Complete proof
  - Knowledge error analysis

### 5. Ring Switching and Sumcheck (`05_ring_switching_sumcheck.md`)
- Unstructured linear relations over R_q
  - Relation definition
  - Input from split-and-fold
- Ring switching technique
  - Lifting to polynomial ring
  - Extension to F_{q^k}[X]
  - Coefficient representation
  - Gadget decomposition of quotient
- Random evaluation (Figure 4)
  - Protocol overview
  - Soundness analysis (Lemma 9)
  - Soundness error
- Multilinear extension of witness
  - Witness vector structure
  - Multilinear extension
  - Commitment
- Constraint polynomials
  - Public polynomials (α̃, M̃_α)
  - Linear constraint polynomial H_α
  - Norm constraint polynomial H_0
- Random point evaluation (Figure 5)
  - Protocol overview
  - Soundness analysis (Lemma 10)
- Sumcheck protocol (Figure 6)
  - Generic sumcheck for H(X) = P(X)·Q(w̃(X))
  - Soundness (Lemma 11)
  - Application to H_0 and H_α
  - Communication cost per round
- Final evaluation proof
  - Evaluation claim
  - Recursive application
  - Termination condition

### 6. Optimizations and Composition (`06_optimizations_composition.md`)
- Avoiding re-decomposition (Section 4.5)
  - Problem statement
  - Multilinear extension structure
  - Homomorphic property of eq
  - Partial evaluation representation
  - Reduction to Greyhound relation
  - Communication cost
- Switching to LaBRADOR
  - Decision point
  - Advantages at small scale
  - Trade-offs
  - Composition protocol
- Challenge space optimization
  - Sparse challenges
  - Efficient sparse multiplication
  - Sampling algorithm
- Complete protocol flow
  - Iteration 1: Field extension to R_q
  - Iteration 1: Ring switching and sumcheck
  - Iteration 2+: Recursive application
  - Final step: LaBRADOR or direct send
- Asymptotic analysis
  - Witness length reduction
  - Proof size per iteration
  - Verifier time per iteration
  - Comparison with Greyhound
- Parameter selection guidelines
  - Security parameters
  - Ring dimension
  - Decomposition base
  - Split parameters
  - Challenge parameters

### 7. Concrete Parameters and Implementation (`07_concrete_parameters_implementation.md`)
- Concrete parameter selection (ℓ = 30)
  - Security parameters
  - Ring parameters
  - Commitment parameters
  - Split parameters
  - Decomposition parameters
  - Folding parameters
  - Ring switching parameters
  - Next iteration parameters
- Proof size breakdown
  - First iteration components
  - Second iteration components
  - Greyhound protocol
  - Total proof size
- Verification time breakdown
  - Per-component analysis
  - Total verification time
  - Comparison with Greyhound
- Prover time breakdown
  - Per-component analysis
  - Total prover time
- Implementation requirements
  - Arithmetic operations (F_q, F_{q^k}, R_q)
  - NTT implementation
  - Sparse polynomial multiplication
  - Multilinear extension evaluation
  - Commitment scheme
  - Fiat-Shamir transform
- Memory requirements
  - Prover memory
  - Verifier memory
  - Streaming witness
- Testing requirements
  - Unit tests
  - Integration tests
  - Security tests
  - Performance tests

### 8. Complete Requirements Specification (`08_complete_requirements_specification.md`)
- System overview
  - Purpose
  - Core components
  - Dependencies
- Functional requirements (FR1-FR5)
  - FR1: Field extension embedding
  - FR2: Commitment scheme
  - FR3: Split-and-fold protocol
  - FR4: Ring switching and sumcheck
  - FR5: Optimizations
- Non-functional requirements (NFR1-NFR4)
  - NFR1: Performance
  - NFR2: Security
  - NFR3: Usability
  - NFR4: Maintainability
- Interface requirements (IR1-IR2)
  - Input formats
  - Output formats
- Data requirements (DR1-DR2)
  - Storage
  - Memory
- Constraint requirements (CR1-CR2)
  - Parameter constraints
  - Resource constraints
- Quality requirements (QR1-QR4)
  - Correctness
  - Reliability
  - Portability
  - Scalability
- Acceptance criteria (AC1-AC4)
  - Functional tests
  - Performance tests
  - Security tests
  - Code quality
- Deliverables (D1-D4)
  - Source code
  - Documentation
  - Benchmarks
  - Examples
- Timeline and milestones (M1-M6)
  - Foundation
  - Commitment
  - Ring switching
  - Optimizations
  - Testing and documentation
  - Release

## Key Insights

### 1. Main Innovation
Hachi achieves Õ(λ) asymptotic improvement in verification time over Greyhound by:
- Integrating ring-switching technique with Greyhound framework
- Running sumcheck over extension field F_{q^k} instead of cyclotomic ring R_q
- Eliminating all cyclotomic ring operations from verifier

### 2. Technical Breakthrough
The verifier performs NO ring operations:
- All verification done over small extension field F_{q^k}
- Sumcheck protocol operates on field elements, not ring elements
- Multilinear extension evaluation uses dynamic programming over F_{q^k}

### 3. Practical Impact
Concrete improvements for ℓ=30 variables:
- Verification: 2.8s → 227ms (12.3× faster)
- Proof size: 53KB → 55KB (comparable)
- Commitment: 3-5× faster (larger ring dimension)

### 4. Flexibility
Unlike Greyhound/LaBRADOR:
- Not constrained to small ring dimensions
- Can use d=1024 instead of d=64
- Enables sparse challenges and faster NTT
- Sumcheck cost independent of d

### 5. Composition Strategy
Optimal approach combines both:
- Use Hachi for first iteration(s) - fast verification
- Switch to LaBRADOR when witness small - fast witness reduction
- Gets best of both worlds

## Implementation Roadmap

### Phase 1: Foundation (Weeks 1-4)
- Implement field arithmetic (F_q, F_{q^k})
- Implement ring arithmetic (R_q) with NTT
- Implement Galois automorphisms
- Implement trace map
- Basic unit tests

### Phase 2: Field Extension Embedding (Weeks 5-6)
- Implement subfield identification
- Implement ψ bijection
- Implement inner product property
- Generic transformation (Section 3.1)
- Optimized transformation (Section 3.2)
- Integration tests

### Phase 3: Commitment Scheme (Weeks 7-10)
- Implement gadget matrices and decomposition
- Implement inner commitment
- Implement outer commitment
- Implement split-and-fold protocol
- Weak binding tests
- Coordinate-wise special soundness tests

### Phase 4: Ring Switching (Weeks 11-14)
- Implement polynomial lifting
- Implement multilinear extensions
- Implement constraint polynomials (H_0, H_α)
- Implement random evaluation protocol
- Soundness tests

### Phase 5: Sumcheck Protocol (Weeks 15-16)
- Implement generic sumcheck
- Implement application to H_0 and H_α
- Implement dynamic programming for MLE
- Optimize per-round computation
- Integration tests

### Phase 6: Optimizations (Weeks 17-18)
- Implement avoid re-decomposition
- Implement Greyhound integration
- Implement sparse challenge multiplication
- Performance tuning
- Memory optimization

### Phase 7: Testing and Documentation (Weeks 19-20)
- Comprehensive unit tests
- Integration tests
- Security tests
- Performance benchmarks
- API documentation
- Usage examples

### Phase 8: Release (Week 21)
- Code review
- Final testing
- Documentation review
- Public release

## Usage Example

```rust
use hachi::{Hachi, Parameters, Polynomial, Point};

// Setup
let params = Parameters::new(
    security_level: 128,
    ring_dimension: 1024,
    extension_degree: 4,
    decomposition_base: 16,
);
let hachi = Hachi::new(params);

// Commit to polynomial
let polynomial = Polynomial::random(30); // 30 variables
let commitment = hachi.commit(&polynomial);

// Prove evaluation
let point = Point::random(30);
let value = polynomial.evaluate(&point);
let proof = hachi.prove(&polynomial, &point);

// Verify
let result = hachi.verify(&commitment, &point, &value, &proof);
assert!(result.is_accept());
```

## Performance Characteristics

### Asymptotic Complexity
- Proof size: poly(ℓ, λ)
- Prover time: O(2^ℓ · poly(λ))
- Verifier time: Õ(√(2^ℓ) · λ)

### Concrete Performance (ℓ=30)
- Proof size: ~55 KB
- Prover time: ~270 s (first round)
- Verifier time: ~227 ms (total)
- Memory: ~5 GB (prover), ~13 MB (verifier)

### Comparison with Greyhound
- Verification: 12.3× faster
- Proof size: Comparable
- Commitment: 3-5× faster
- Prover time: Similar

## Security Analysis

### Assumptions
- Module-SIS hardness
- Random Oracle Model (for Fiat-Shamir)

### Security Level
- λ = 128 bits
- Post-quantum secure
- Verified using Lattice Estimator

### Soundness
- Knowledge error: ≤ 2^{-128}
- Coordinate-wise special soundness
- Extraction algorithm provided

### Binding
- Commitment binding under Module-SIS
- Weak binding for extracted openings
- Parameters verified for security

## References

1. Original Paper: "Hachi: Efficient Lattice-Based Multilinear Polynomial Commitments over Extension Fields" (2026)
2. Greyhound: Nguyen & Seiler, CRYPTO 2024
3. LaBRADOR: Beullens & Seiler, CRYPTO 2023
4. Ring Switching: Huang, Mao & Zhang, ePrint 2025
5. Module-SIS: Langlois & Stehlé, DCC 2015

## Contact

For questions or issues with this analysis:
- Open an issue on GitHub
- Contact the authors of the original paper
- Refer to the paper for authoritative information

## License

This analysis is provided for educational and research purposes.
The original paper and its contents are copyright of the authors.
