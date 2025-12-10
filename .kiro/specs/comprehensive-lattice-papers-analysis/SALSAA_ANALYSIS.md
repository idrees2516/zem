# SALSAA: Sumcheck-Aided Lattice-based Succinct Arguments

## Paper Overview
**Authors:** Shuto Kuriyama, Russell W. F. Lai, Michał Osadnik, Lorenzo Tucci  
**Focus:** Efficient lattice-based succinct arguments with linear-time prover  
**Key Innovation:** Sumcheck-based norm-check reducing proof size by 2-3x and prover time to linear

## Core Components

### 1. Framework Extensions (RPS/RnR)
**Building on:** RoK, Paper, SISsors (RPS) and RoK and Roll (RnR)
- **Base Assumption:** Vanishing Short Integer Solution (vSIS)
- **Principal Relation:** Ξlin with structured linear equations
- **Witness Constraint:** ∥W∥ ≤ β (norm-bounded)

### 2. Novel Norm-Check Protocol (Πnorm)
**Key Innovation:** Replaces quasi-linear norm-check with linear-time sumcheck-based approach

**Previous Approach (Πklno24):**
- Multiplies two polynomials of degree m
- Complexity: O(m log m)
- Commits to multiplication result as witness columns
- Proof size overhead: 2-3x

**New Approach (Πnorm):**
- Expresses norm claim as sumcheck over LDE
- Complexity: O(m) linear time
- Evaluation claim without witness expansion
- Proof size: 2-3x reduction

### 3. Low-Degree Extension (LDE) Relations
**Ξlde:** Extends Ξlin to check LDE evaluations
- **Property:** LDE[w](ri) = si mod q for all i ∈ [t]
- **Reduction:** LDE evaluation claims → Ξlin via tensor structure
- **Benefit:** Captures polynomial evaluation claims naturally

### 4. Sumcheck Relation (Ξsum)
**Definition:** Extends Ξlin to check sumcheck claims over LDEs
- **Reduction Path:** Ξsum → Ξlde-⊗ → Ξlin
- **Prover Complexity:** Linear in witness size
- **Verifier Complexity:** Polylog in witness size

### 5. Modular RoK Composition
**Available RoKs:**
- Πjoin: Joins multiple instances
- Π⊗RP: Random projection
- Πfold: Folding reduction
- Πb-decomp: Base decomposition
- Πnorm: Norm-check (novel)
- Πsum: Sumcheck reduction (novel)
- Πlde-⊗: LDE evaluation
- Πbatch*: Batching protocol (novel variant)

## Missing Components & Required Implementations

### A. Theoretical Foundations

1. **Formal Sumcheck-Norm Reduction**
   - Missing: Complete proof of Πnorm correctness
   - Required: Formal specification of norm-to-sumcheck reduction
   - Acceptance Criteria:
     - Soundness error: ≤ negl(λ)
     - Completeness: 1 - negl(λ)
     - Prover complexity: O(m) field operations
     - Verifier complexity: O(log m) field operations

2. **LDE Relation Formalization**
   - Missing: Complete definition of Ξlde and Ξlde-⊗
   - Required: Formal reduction proofs to Ξlin
   - Acceptance Criteria:
     - Reduction preserves soundness
     - Reduction overhead: O(t) field operations
     - Support arbitrary LDE evaluation points

3. **Composition Soundness**
   - Missing: Formal proof of RoK composition soundness
   - Required: Analysis of soundness loss across compositions
   - Acceptance Criteria:
     - Total soundness error: negl(λ)
     - Per-composition loss: ≤ 1/poly(λ)
     - Supports arbitrary composition depth

### B. Protocol Specifications

1. **R1CS Support**
   - Missing: Complete RoK from R1CS to Ξlin
   - Required: Detailed constraint reduction protocol
   - Acceptance Criteria:
     - Support arbitrary R1CS relations
     - Reduction overhead: O(n) field operations
     - Verifier complexity: polylog(n)

2. **Polynomial Commitment Scheme (PCS)**
   - Missing: Complete PCS construction from SALSAA
   - Required: Detailed protocol for polynomial evaluation proofs
   - Acceptance Criteria:
     - Prover: O(n) field operations
     - Verifier: polylog(n) field operations
     - Proof size: polylog(n) elements
     - Support multilinear and univariate polynomials

3. **Folding Scheme Implementation**
   - Missing: Complete folding scheme using SALSAA RoKs
   - Required: Detailed protocol for instance folding
   - Acceptance Criteria:
     - Fold ℓ instances in single shot
     - Prover: O(ℓn) field operations
     - Verifier: O(ℓ) field operations
     - Proof size: O(log n + log ℓ) elements

### C. Implementation Requirements

1. **Sumcheck Protocol Optimization**
   - Missing: Optimized sumcheck implementation
   - Required: Dynamic programming-based prover
   - Acceptance Criteria:
     - Prover: O(m) field operations (linear)
     - Memory: O(m) for witness storage
     - Parallelizable across variables
     - Hardware acceleration support (AVX-512)

2. **Norm-Check Protocol Implementation**
   - Missing: Efficient Πnorm implementation
   - Required: Optimized LDE evaluation and sumcheck integration
   - Acceptance Criteria:
     - Prover: O(m) field operations
     - Proof size: 2-3x smaller than RPS/RnR
     - Verifier: polylog(m) field operations
     - Constant-time operations for security

3. **Batching Protocol (Πbatch*)**
   - Missing: Complete specification of novel batching
   - Required: Efficient protocol for folding scheme batching
   - Acceptance Criteria:
     - Batch ℓ instances efficiently
     - Prover: O(ℓn) field operations
     - Verifier: O(ℓ) field operations
     - Proof size: O(log ℓ) elements

### D. Cryptographic Assumptions

1. **vSIS Assumption Formalization**
   - Missing: Complete formal definition
   - Required: Security parameter selection guidelines
   - Acceptance Criteria:
     - Formal hardness assumption
     - Reduction from standard lattice problems
     - Security loss: poly(λ)

2. **Module SIS Reduction**
   - Missing: Formal reduction from Module SIS to vSIS
   - Required: Detailed security proof
   - Acceptance Criteria:
     - Reduction preserves security
     - Security loss: poly(λ)
     - Supports arbitrary ring dimensions

### E. Performance Optimization

1. **NTT-Based Ring Arithmetic**
   - Missing: Optimized NTT implementation
   - Required: AVX-512 accelerated cyclotomic ring operations
   - Acceptance Criteria:
     - 10-100x speedup over naive implementation
     - Support incomplete NTT for small fields
     - Constant-time operations

2. **Proof Size Reduction**
   - Missing: Techniques to further reduce proof size
   - Required: Compression strategies beyond 2-3x
   - Acceptance Criteria:
     - Proof size: < 1 MB for 2^28 witness elements
     - Compression ratio: ≥ 2x vs. RPS/RnR
     - Verifier time: < 50 ms

3. **Prover Parallelization**
   - Missing: Detailed parallel algorithm
   - Required: Work distribution strategy
   - Acceptance Criteria:
     - Linear speedup with p processors for p ≤ m
     - Communication overhead: O(log p) per round
     - Memory: O(m/p) per processor

### F. Application Implementations

1. **SNARK Application**
   - Missing: Complete SNARK construction
   - Required: Integration of all RoKs
   - Acceptance Criteria:
     - Verifier: 41 ms for 2^28 witness
     - Prover: 10.61 s for 2^28 witness
     - Proof size: 979 KB
     - Support arbitrary NP relations

2. **PCS Application**
   - Missing: Complete PCS construction
   - Required: Polynomial evaluation argument
   - Acceptance Criteria:
     - Verifier: < 50 ms
     - Prover: < 15 s for 2^28 elements
     - Proof size: < 1 MB
     - Support multilinear and univariate

3. **Folding Scheme Application**
   - Missing: Complete folding scheme
   - Required: Efficient instance folding
   - Acceptance Criteria:
     - Verifier: 2.28 ms for 4 instances
     - Prover: < 5 s for 2^28 witness
     - Proof size: 73 KB
     - Support ℓ2-norm-bounded witnesses

## Acceptance Criteria Summary

### Functional Requirements
- [ ] Linear-time norm-check protocol
- [ ] Support R1CS, Plonkish, and AIR constraints
- [ ] Modular RoK composition framework
- [ ] Polynomial commitment scheme
- [ ] Folding scheme with ℓ2-norm support
- [ ] Batching protocol for folding

### Performance Requirements
- [ ] Norm-check prover: O(m) linear time
- [ ] Proof size: 2-3x reduction vs. RPS/RnR
- [ ] SNARK verifier: < 50 ms for 2^28 witness
- [ ] SNARK prover: < 15 s for 2^28 witness
- [ ] Folding verifier: < 3 ms for 4 instances
- [ ] Proof size: < 1 MB for 2^28 elements

### Security Requirements
- [ ] Knowledge soundness: negl(λ) error
- [ ] vSIS assumption hardness
- [ ] Constant-time operations
- [ ] Post-quantum security
- [ ] Formal security proofs

### Testing Requirements
- [ ] Property-based tests for all RoKs
- [ ] Soundness verification across constraint types
- [ ] Performance benchmarks vs. RPS/RnR
- [ ] Security proofs formalized
- [ ] Hardware acceleration validation
