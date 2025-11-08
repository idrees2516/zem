# Requirements Document: LatticeFold+ and Neo Integration

## Introduction

This specification defines the requirements for integrating the LatticeFold+ implementation with the Neo lattice-based zkVM. The goal is to create a unified, production-ready lattice-based zero-knowledge virtual machine that combines:

1. **LatticeFold+** components from the `LatticeFold+` folder - providing advanced lattice reduction, commitment schemes, and folding protocols
2. **Neo** implementation from `neo-lattice-zkvm` - providing small field optimization, CCS reduction, and IVC infrastructure

The integration will leverage the strengths of both implementations, fill any gaps, and create a cohesive system that is quantum-resistant, efficient, and production-ready.

## Glossary

- **Neo**: Lattice-based folding scheme for CCS over small fields with pay-per-bit commitments
- **LatticeFold+**: Faster, simpler, shorter lattice-based folding scheme with algebraic range proofs
- **CCS**: Customizable Constraint System - a generalization of R1CS and Plonkish arithmetization
- **IVC**: Incremental Verifiable Computation - recursive proof composition
- **Ajtai Commitment**: Lattice-based commitment scheme based on the SIS problem
- **Module-SIS**: Module Short Integer Solution problem - security foundation for lattice commitments
- **NTT**: Number Theoretic Transform - fast polynomial multiplication in cyclotomic rings
- **BKZ**: Block Korkine-Zolotarev - lattice basis reduction algorithm
- **Cyclotomic Ring**: Polynomial ring R = Zq[X]/(X^d + 1) used in lattice cryptography
- **Monomial Set**: Set M = {0, ±1, ±X, ..., ±X^(d-1)} used for algebraic range proofs
- **Gadget Decomposition**: Base-b decomposition G^(-1) for norm reduction
- **Sum-check Protocol**: Interactive proof for polynomial evaluations
- **Fiat-Shamir**: Transform interactive proofs to non-interactive using hash functions

## Requirements

### Requirement 1: Core Component Integration

**User Story:** As a zkVM developer, I want to integrate LatticeFold+ components with Neo infrastructure, so that I can leverage both implementations' strengths.

#### Acceptance Criteria

1. WHEN integrating cyclotomic ring operations, THE Integration_System SHALL reuse Neo's NTT engine for polynomial multiplication
2. WHEN integrating commitment schemes, THE Integration_System SHALL unify Ajtai commitments from both implementations
3. WHEN integrating field arithmetic, THE Integration_System SHALL support both Goldilocks and M61 fields from Neo
4. WHEN integrating lattice operations, THE Integration_System SHALL use LatticeFold+ lattice basis and reduction algorithms
5. WHEN integrating challenge generation, THE Integration_System SHALL use Neo's transcript-based Fiat-Shamir transform

### Requirement 2: Lattice Reduction Integration

**User Story:** As a cryptographer, I want to integrate LatticeFold+ lattice reduction algorithms, so that the system has production-ready basis reduction capabilities.

#### Acceptance Criteria

1. WHEN performing lattice basis reduction, THE Integration_System SHALL use LatticeFold+ BKZ reduction with configurable block sizes
2. WHEN performing LLL reduction, THE Integration_System SHALL use LatticeFold+ LLL implementation as preprocessing
3. WHEN computing SVP solutions, THE Integration_System SHALL use LatticeFold+ SVP oracle
4. WHEN optimizing basis quality, THE Integration_System SHALL use LatticeFold+ tour optimizer for BKZ
5. WHEN validating security parameters, THE Integration_System SHALL verify Module-SIS hardness using lattice estimators

### Requirement 3: Commitment Scheme Unification

**User Story:** As a protocol designer, I want unified commitment schemes, so that both linear and double commitments work seamlessly together.

#### Acceptance Criteria

1. WHEN creating Ajtai commitments, THE Integration_System SHALL merge implementations from both LatticeFold+ and Neo
2. WHEN creating SIS commitments, THE Integration_System SHALL use LatticeFold+ SIS commitment with opening proofs
3. WHEN performing commitment operations, THE Integration_System SHALL support homomorphic addition and scalar multiplication
4. WHEN batching commitments, THE Integration_System SHALL use Neo's parallel processing infrastructure
5. WHEN verifying commitments, THE Integration_System SHALL use optimized verification from both implementations

### Requirement 4: Monomial Set Check Protocol

**User Story:** As a prover, I want to prove that matrices contain only monomials, so that I can use algebraic range proofs instead of bit decomposition.

#### Acceptance Criteria

1. WHEN proving monomial set membership, THE Integration_System SHALL implement the Π_mon protocol from LatticeFold+
2. WHEN verifying monomial proofs, THE Integration_System SHALL use degree-3 sum-check from Neo's infrastructure
3. WHEN batching monomial checks, THE Integration_System SHALL combine multiple matrices into single sum-check
4. WHEN computing monomial commitments, THE Integration_System SHALL optimize to use only ring additions
5. WHEN evaluating monomials, THE Integration_System SHALL verify a(X²) = a(X)² property efficiently

### Requirement 5: Algebraic Range Proof Protocol

**User Story:** As a prover, I want to prove range constraints algebraically, so that I can avoid expensive bit decomposition.

#### Acceptance Criteria

1. WHEN proving range constraints, THE Integration_System SHALL implement Π_rgchk protocol using table polynomials
2. WHEN decomposing witnesses, THE Integration_System SHALL use gadget decomposition G^(-1)_{d',k}
3. WHEN verifying ranges, THE Integration_System SHALL use constant-term extraction ct(b·ψ) = a
4. WHEN batching range proofs, THE Integration_System SHALL combine monomial checks for decomposition and split vectors
5. WHEN computing table polynomials, THE Integration_System SHALL precompute and cache ψ = Σ i·(X^(-i) + X^i)

### Requirement 6: Commitment Transformation Protocol

**User Story:** As a protocol implementer, I want to transform commitments between schemes, so that I can fold instances efficiently.

#### Acceptance Criteria

1. WHEN transforming commitments, THE Integration_System SHALL implement Π_cm protocol with double commitments
2. WHEN computing split vectors, THE Integration_System SHALL use split(com(M)) = G^(-1)(com(M)) flattened
3. WHEN computing power functions, THE Integration_System SHALL verify pow(split(D)) = D property
4. WHEN folding commitments, THE Integration_System SHALL use challenge sets from Neo's infrastructure
5. WHEN running sum-checks, THE Integration_System SHALL batch evaluation and consistency claims

### Requirement 7: L-to-2 Folding Protocol

**User Story:** As a folding scheme user, I want to fold L instances into 2 instances, so that I can achieve logarithmic verification.

#### Acceptance Criteria

1. WHEN folding L instances, THE Integration_System SHALL implement main folding protocol combining range checks and commitment transformations
2. WHEN decomposing folded witnesses, THE Integration_System SHALL split f = f_low + B·f_high with norm reduction
3. WHEN verifying folding, THE Integration_System SHALL check all range proofs and commitment transformations
4. WHEN computing folded commitments, THE Integration_System SHALL use random linear combinations over challenge set
5. WHEN outputting instances, THE Integration_System SHALL produce 2 instances with norm bound B

### Requirement 8: IVC Integration

**User Story:** As a zkVM developer, I want incremental verifiable computation, so that I can build recursive proof systems.

#### Acceptance Criteria

1. WHEN performing IVC, THE Integration_System SHALL integrate LatticeFold+ folding with Neo's IVC infrastructure
2. WHEN accumulating proofs, THE Integration_System SHALL use Neo's accumulation scheme
3. WHEN compressing proofs, THE Integration_System SHALL use Neo's compression techniques
4. WHEN verifying recursively, THE Integration_System SHALL support arbitrary depth recursion
5. WHEN managing state, THE Integration_System SHALL use Neo's state management for incremental computation

### Requirement 9: Small Field Optimization

**User Story:** As a performance engineer, I want small field optimizations, so that the system works efficiently with 64-bit fields.

#### Acceptance Criteria

1. WHEN using small fields, THE Integration_System SHALL implement Neo's tensor-of-rings framework
2. WHEN computing embeddings, THE Integration_System SHALL use extension fields F_q^t for sufficient challenge space
3. WHEN performing sum-checks, THE Integration_System SHALL decompose ring claims into field claims
4. WHEN sampling challenges, THE Integration_System SHALL ensure challenge set size ≥ 2^λ for security parameter λ
5. WHEN optimizing NTT, THE Integration_System SHALL use Neo's NTT engine with precomputed twiddle factors

### Requirement 10: Parallel Processing Integration

**User Story:** As a performance engineer, I want parallel processing, so that the system utilizes multi-core processors efficiently.

#### Acceptance Criteria

1. WHEN computing commitments, THE Integration_System SHALL use Neo's parallel commitment computation
2. WHEN performing matrix operations, THE Integration_System SHALL use LatticeFold+ parallel folding infrastructure
3. WHEN running sum-checks, THE Integration_System SHALL parallelize polynomial evaluations
4. WHEN batching operations, THE Integration_System SHALL use Neo's batch processor with work-stealing
5. WHEN managing threads, THE Integration_System SHALL use Rayon for automatic thread pool management

### Requirement 11: Memory Optimization Integration

**User Story:** As a system engineer, I want memory optimizations, so that the system handles large witnesses efficiently.

#### Acceptance Criteria

1. WHEN allocating memory, THE Integration_System SHALL use Neo's memory pooling infrastructure
2. WHEN processing large witnesses, THE Integration_System SHALL use streaming computation
3. WHEN caching data, THE Integration_System SHALL use Neo's NTT cache and LatticeFold+ precomputation
4. WHEN managing buffers, THE Integration_System SHALL use pooled buffers with RAII lifecycle
5. WHEN detecting memory pressure, THE Integration_System SHALL trigger garbage collection appropriately

### Requirement 12: Security Parameter Validation

**User Story:** As a security engineer, I want comprehensive security validation, so that the system meets 128-bit security requirements.

#### Acceptance Criteria

1. WHEN validating parameters, THE Integration_System SHALL verify Module-SIS security ≥ 128 bits
2. WHEN computing soundness error, THE Integration_System SHALL ensure total error ≤ 2^-128
3. WHEN selecting challenge sets, THE Integration_System SHALL verify |C| ≥ 2^128
4. WHEN choosing norm bounds, THE Integration_System SHALL ensure β_SIS = 2b||S||_op is sufficient
5. WHEN configuring fields, THE Integration_System SHALL support 128, 192, and 256-bit security levels

### Requirement 13: Adaptive Security Integration

**User Story:** As a cryptographer, I want adaptive security, so that the system resists adaptive attacks.

#### Acceptance Criteria

1. WHEN implementing adaptive security, THE Integration_System SHALL use LatticeFold+ adaptive security wrapper
2. WHEN committing to statements, THE Integration_System SHALL use statement commitments with challenges
3. WHEN proving adaptively, THE Integration_System SHALL support adaptive relation selection
4. WHEN verifying adaptively, THE Integration_System SHALL check proof consistency across challenges
5. WHEN binding commitments, THE Integration_System SHALL ensure adaptive binding via SIS hardness

### Requirement 14: Zero-Knowledge Property

**User Story:** As a privacy engineer, I want zero-knowledge proofs, so that witnesses remain private.

#### Acceptance Criteria

1. WHEN generating proofs, THE Integration_System SHALL use LatticeFold+ ZK folding with blinding
2. WHEN sampling randomness, THE Integration_System SHALL use quantum-resistant sampling
3. WHEN masking witnesses, THE Integration_System SHALL add appropriate noise for zero-knowledge
4. WHEN simulating proofs, THE Integration_System SHALL support simulation for security proofs
5. WHEN verifying ZK proofs, THE Integration_System SHALL not leak witness information

### Requirement 15: Quantum Resistance

**User Story:** As a cryptographer, I want quantum resistance, so that the system remains secure against quantum computers.

#### Acceptance Criteria

1. WHEN selecting parameters, THE Integration_System SHALL use lattice-based cryptography throughout
2. WHEN computing security, THE Integration_System SHALL account for quantum attacks (BKZ with quantum speedup)
3. WHEN sampling challenges, THE Integration_System SHALL use quantum-resistant PRGs
4. WHEN reducing lattices, THE Integration_System SHALL use BKZ with sufficient block size for quantum security
5. WHEN validating hardness, THE Integration_System SHALL use conservative quantum security estimates

### Requirement 16: API Design and Usability

**User Story:** As an application developer, I want clean APIs, so that I can integrate the zkVM into applications easily.

#### Acceptance Criteria

1. WHEN using the system, THE Integration_System SHALL provide high-level prove() and verify() methods
2. WHEN configuring parameters, THE Integration_System SHALL provide builder pattern for configuration
3. WHEN handling errors, THE Integration_System SHALL provide comprehensive error types with context
4. WHEN managing state, THE Integration_System SHALL use RAII for resource management
5. WHEN documenting APIs, THE Integration_System SHALL provide examples and usage documentation

### Requirement 17: Testing and Validation

**User Story:** As a quality engineer, I want comprehensive testing, so that the system is reliable and correct.

#### Acceptance Criteria

1. WHEN testing components, THE Integration_System SHALL include unit tests for all modules
2. WHEN testing integration, THE Integration_System SHALL include end-to-end integration tests
3. WHEN testing security, THE Integration_System SHALL verify cryptographic properties
4. WHEN testing performance, THE Integration_System SHALL include benchmarks for critical paths
5. WHEN testing compatibility, THE Integration_System SHALL verify cross-platform operation

### Requirement 18: Gap Analysis and Implementation

**User Story:** As a system architect, I want to identify and fill implementation gaps, so that the integrated system is complete.

#### Acceptance Criteria

1. WHEN analyzing LatticeFold+, THE Integration_System SHALL identify missing components in Neo
2. WHEN analyzing Neo, THE Integration_System SHALL identify missing components in LatticeFold+
3. WHEN finding gaps, THE Integration_System SHALL implement missing functionality
4. WHEN integrating components, THE Integration_System SHALL resolve API incompatibilities
5. WHEN completing integration, THE Integration_System SHALL verify all requirements are met

