# Requirements Document

## Introduction

This specification addresses the production-readiness gaps in the Neo Lattice zkVM implementation. The system currently contains numerous placeholder implementations, simplified algorithms, and TODO comments that must be replaced with cryptographically sound, production-grade implementations. This work is critical for security, correctness, and performance of the zkVM in real-world deployments.

## Glossary

- **Fiat-Shamir Transform**: A technique to convert interactive protocols into non-interactive ones using cryptographic hash functions
- **HyperWolf PCS**: The polynomial commitment scheme used in the system based on lattice assumptions
- **Labrador Protocol**: A specific lattice-based commitment protocol with logarithmic verification time
- **Ajtai Commitment**: A lattice-based cryptographic commitment scheme
- **IVC (Incrementally Verifiable Computation)**: A technique for proving correctness of iterative computations
- **CCS (Customizable Constraint System)**: A generalized constraint system for zkSNARKs
- **Range Check Protocol**: A zero-knowledge protocol proving values lie within specified ranges
- **Lattice Estimator**: A tool for estimating security parameters of lattice-based cryptographic schemes
- **Neo Bridge**: The integration layer between Neo commitments and HyperWolf PCS
- **Symphony SNARK**: The SNARK system used in the zkVM

## Requirements

### Requirement 1: Fiat-Shamir Challenge Generation

**User Story:** As a cryptographic protocol implementer, I want proper Fiat-Shamir challenge generation, so that the non-interactive proofs are cryptographically secure and verifiable.

#### Acceptance Criteria

1. WHEN the Labrador protocol generates challenges, THE System SHALL use cryptographic hash functions to derive challenges from the protocol transcript
2. WHEN the batching protocol requires randomness, THE System SHALL derive challenges using Fiat-Shamir hashing of all prior protocol messages
3. WHEN challenge generation occurs, THE System SHALL include all relevant public inputs and commitments in the hash computation
4. WHEN multiple challenges are needed, THE System SHALL use domain separation to prevent cross-protocol attacks
5. WHERE the hash oracle is invoked, THE System SHALL maintain a complete transcript of all absorbed values

### Requirement 2: Lattice Security Parameter Validation

**User Story:** As a security engineer, I want comprehensive lattice security validation, so that the cryptographic parameters provide the claimed security level against lattice attacks.

#### Acceptance Criteria

1. WHEN Ajtai commitment parameters are initialized, THE System SHALL validate security using a full lattice estimator
2. WHEN security parameters are checked, THE System SHALL verify resistance against BKZ, sieve, and enumeration attacks
3. WHEN parameter validation fails, THE System SHALL return a descriptive error indicating the security gap
4. WHILE the system operates, THE System SHALL enforce minimum security levels of 128 bits
5. WHERE custom parameters are provided, THE System SHALL validate them against current lattice attack estimates

### Requirement 3: Labrador Verification Complexity

**User Story:** As a verifier, I want logarithmic-time verification in the Labrador protocol, so that proof verification scales efficiently with proof size.

#### Acceptance Criteria

1. WHEN Labrador verification occurs, THE System SHALL verify that non-zero element count is O(log N)
2. IF the non-zero count exceeds O(log N), THEN THE System SHALL reject the proof with a complexity violation error
3. WHEN verification completes, THE System SHALL ensure total verification time is O(log N)
4. WHILE verifying proofs, THE System SHALL track and validate sparsity constraints
5. WHERE verification occurs, THE System SHALL enforce structural constraints on proof elements

### Requirement 4: CCS Reduction Setup Precomputation

**User Story:** As a performance engineer, I want precomputed CCS reduction matrices, so that proof generation is efficient and doesn't recompute expensive operations.

#### Acceptance Criteria

1. WHEN CCS reduction setup occurs, THE System SHALL precompute all reduction matrices during the setup phase
2. WHEN reduction matrices are needed, THE System SHALL retrieve them from precomputed storage
3. WHEN setup completes, THE System SHALL serialize and store all precomputed values
4. WHILE generating proofs, THE System SHALL use only precomputed matrices without on-demand computation
5. WHERE Ajtai commitments are used in CCS, THE System SHALL precompute commitment keys during setup

### Requirement 5: Recursive SNARK Aggregation

**User Story:** As a proof system developer, I want proper recursive SNARK verification, so that multiple proofs can be efficiently aggregated and verified.

#### Acceptance Criteria

1. WHEN aggregating proofs, THE System SHALL use recursive SNARK composition for efficiency
2. WHEN verifying aggregated proofs, THE System SHALL validate the recursive SNARK verification
3. WHEN proof batching occurs, THE System SHALL verify batching correctness using the batching protocol
4. WHEN accumulator updates happen, THE System SHALL verify accumulator consistency across aggregation steps
5. WHERE compression is applied, THE System SHALL maintain soundness through proper recursive verification

### Requirement 6: IVC Verification Completeness

**User Story:** As an IVC user, I want complete verification of incremental computations, so that the entire computation chain is cryptographically verified.

#### Acceptance Criteria

1. WHEN IVC verification occurs, THE System SHALL verify accumulator validity at each step
2. WHEN folding steps are verified, THE System SHALL check folding correctness for each computation step
3. WHEN final verification happens, THE System SHALL verify the final SNARK proof
4. WHEN state transitions occur, THE System SHALL verify state transition consistency across all steps
5. WHERE IVC chains are verified, THE System SHALL ensure no gaps exist in the verification chain

### Requirement 7: Production Commitment Implementations

**User Story:** As a commitment scheme user, I want actual cryptographic commitments instead of placeholders, so that the system provides binding and hiding properties.

#### Acceptance Criteria

1. WHEN double commitments are created in LatticeFold, THE System SHALL use the actual commitment scheme
2. WHEN range check commitments are generated, THE System SHALL compute them using the configured commitment scheme
3. WHEN commitments are created, THE System SHALL ensure binding and hiding properties
4. WHILE generating commitments, THE System SHALL use proper randomness from secure sources
5. WHERE commitments are verified, THE System SHALL perform full cryptographic verification

### Requirement 8: Proper Serialization and Parsing

**User Story:** As a system integrator, I want robust serialization, so that proofs and parameters can be reliably stored and transmitted.

#### Acceptance Criteria

1. WHEN CP-SNARK proofs are serialized, THE System SHALL use a well-defined binary format
2. WHEN parsing occurs, THE System SHALL validate all input data for correctness and bounds
3. WHEN serialization errors occur, THE System SHALL return descriptive error messages
4. WHILE deserializing, THE System SHALL reject malformed or invalid data
5. WHERE version compatibility matters, THE System SHALL include version information in serialized data

### Requirement 9: Witness Generation

**User Story:** As a zkVM user, I want proper witness generation, so that proofs correctly represent the computation being verified.

#### Acceptance Criteria

1. WHEN witnesses are created for padding, THE System SHALL generate valid witnesses that satisfy constraints
2. WHEN witness generation occurs, THE System SHALL ensure all constraint system requirements are met
3. WHEN dummy witnesses are needed, THE System SHALL create witnesses that are indistinguishable from real ones
4. WHILE generating witnesses, THE System SHALL validate consistency with public inputs
5. WHERE witnesses are used in proofs, THE System SHALL ensure they satisfy all circuit constraints

### Requirement 10: Compiler Verification

**User Story:** As a compiler user, I want verification of compiled circuits, so that the compilation process is correct and complete.

#### Acceptance Criteria

1. WHEN circuit compilation completes, THE System SHALL verify the compiled circuit structure
2. WHEN verification occurs, THE System SHALL check constraint satisfaction for test inputs
3. WHEN compilation errors exist, THE System SHALL report specific constraint violations
4. WHILE verifying circuits, THE System SHALL validate all gate connections and wire assignments
5. WHERE optimization occurs, THE System SHALL verify that optimizations preserve circuit semantics

### Requirement 11: Secure Randomness Sources

**User Story:** As a security engineer, I want cryptographically secure randomness, so that all random values are unpredictable and uniformly distributed.

#### Acceptance Criteria

1. WHEN randomness is needed for extraction, THE System SHALL use a cryptographically secure random number generator
2. WHEN random challenges are generated, THE System SHALL ensure uniform distribution over the challenge space
3. WHEN randomness generation fails, THE System SHALL return an error rather than using weak randomness
4. WHILE generating random values, THE System SHALL use platform-specific secure random sources
5. WHERE deterministic randomness is needed, THE System SHALL use proper PRF constructions with unique seeds

### Requirement 12: HyperWolf Core Protocol Verification

**User Story:** As a protocol implementer, I want complete HyperWolf verification, so that all protocol steps are cryptographically validated.

#### Acceptance Criteria

1. WHEN HyperWolf core protocol verification occurs, THE System SHALL verify the complete matrix equation
2. WHEN ring element validation happens, THE System SHALL use proper MR and G^{-1} transformations
3. WHEN protocol steps are verified, THE System SHALL check all intermediate values for correctness
4. WHILE verifying proofs, THE System SHALL validate all ring operations and modular reductions
5. WHERE simplified checks exist, THE System SHALL replace them with full cryptographic verification

### Requirement 13: Neo Bridge Production Implementation

**User Story:** As a Neo integration developer, I want proper Neo-to-HyperWolf bridging, so that Neo commitments are correctly transformed for HyperWolf verification.

#### Acceptance Criteria

1. WHEN Neo commitments are bridged to HyperWolf, THE System SHALL restructure them into proper leveled format
2. WHEN commitment verification occurs across the bridge, THE System SHALL perform full cryptographic checks
3. WHEN bridging happens, THE System SHALL preserve all security properties of the original commitment
4. WHILE transforming commitments, THE System SHALL validate structural compatibility
5. WHERE format conversion occurs, THE System SHALL ensure no information is lost or corrupted

### Requirement 14: Range Check Protocol Completeness

**User Story:** As a range proof user, I want complete range check implementations, so that range proofs are sound and verifiable.

#### Acceptance Criteria

1. WHEN range proofs are generated, THE System SHALL create complete monomial proofs
2. WHEN range check commitments are needed, THE System SHALL compute them using the actual commitment scheme
3. WHEN range verification occurs, THE System SHALL extract and verify linear instances
4. WHEN range witnesses are needed, THE System SHALL extract proper linear witnesses
5. WHERE range proofs are used, THE System SHALL ensure they prove the claimed range bounds

### Requirement 15: Single Instance Protocol Integration

**User Story:** As a protocol developer, I want proper challenge sharing and instance extraction, so that the single instance protocol is correctly integrated with other components.

#### Acceptance Criteria

1. WHEN single instance proofs are created, THE System SHALL compute proper commitments using the range prover
2. WHEN challenges are shared, THE System SHALL extract them from the actual protocol execution
3. WHEN linear instances are extracted, THE System SHALL derive them from range proofs correctly
4. WHEN linear witnesses are extracted, THE System SHALL ensure consistency with the range proof
5. WHERE sumcheck execution occurs, THE System SHALL properly share challenges across protocol components

### Requirement 16: Symphony-HyperWolf Integration

**User Story:** As a Symphony SNARK user, I want complete HyperWolf PCS integration, so that polynomial evaluations are properly committed and verified.

#### Acceptance Criteria

1. WHEN Symphony verification occurs with HyperWolf, THE System SHALL call HyperWolf PCS verify_eval
2. WHEN polynomial commitments are created, THE System SHALL use the actual commitment key
3. WHEN evaluation proofs are verified, THE System SHALL perform full cryptographic verification
4. WHILE integrating HyperWolf with Symphony, THE System SHALL ensure all interfaces are correctly implemented
5. WHERE batching is used, THE System SHALL call the actual HyperWolf prove_eval method

### Requirement 17: IVC Folding Implementation

**User Story:** As an IVC user, I want proper proof folding, so that incremental computations are efficiently accumulated.

#### Acceptance Criteria

1. WHEN IVC accumulation occurs, THE System SHALL fold new proofs with accumulated proofs using the folding protocol
2. WHEN folding happens, THE System SHALL verify folding correctness at each step
3. WHEN accumulator updates occur, THE System SHALL maintain accumulator consistency
4. WHILE folding proofs, THE System SHALL ensure soundness is preserved across folding operations
5. WHERE multiple proofs are accumulated, THE System SHALL use efficient batching techniques
