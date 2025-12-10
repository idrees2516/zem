# Implementation Plan: AGM-Secure Functionalities with Cryptographic Proofs

## Overview

This implementation plan breaks down the AGM-Secure IVC framework into discrete, manageable coding tasks. Each task builds incrementally on previous work, ensuring the system can be developed and tested step-by-step. The plan focuses exclusively on code implementation tasks that can be executed by a coding agent.

---

## Task List

- [x] 1. Set up AGM module foundation


  - Create module structure for AGM (Algebraic Group Model) components
  - Implement core traits for Field and Group elements with serialization
  - Implement GroupRepresentation data structure for tracking basis elements and coefficients
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 4.1, 4.2, 4.3, 4.4, 4.5_

- [x] 2. Implement group representation management

  - [x] 2.1 Implement GroupRepresentation manager with add_basis_element and provide_representation methods


    - Write methods for adding basis elements and storing representations
    - Implement verify_representation to check y = Γ^T x
    - Add representation_map for efficient lookups
    - _Requirements: 1.1, 1.2, 1.3_
  
  - [x] 2.2 Implement AlgebraicOutput structure and AlgebraicAdversary trait

    - Create AlgebraicOutput struct with output_elements, oracle_queried_elements, and representations
    - Define AlgebraicAdversary trait with run and verify_algebraic methods
    - _Requirements: 1.1, 1.2, 1.3_
  

  - [x] 2.3 Implement GroupParser for extracting group elements from mixed data

    - Write parse method to extract group elements from byte arrays
    - Implement extract_from_statement_proof for parsing statements and proofs
    - Add compute_oracle_forcing_set for set difference computation
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [x] 3. Implement oracle model infrastructure


  - [x] 3.1 Create oracle transcript management


    - Implement OracleQuery and OracleTranscript structures
    - Write Oracle trait with query, transcript, and is_consistent methods
    - Add transcript recording and consistency checking
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  

  - [ ] 3.2 Implement Random Oracle Model (ROM)
    - Create RandomOracle struct with ChaCha20Rng
    - Implement Oracle trait for RandomOracle with caching
    - Add query method with transcript recording
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

  
  - [ ] 3.3 Implement Arithmetized Random Oracle Model (AROM)
    - Create AROM struct with ro, wo, and vco components
    - Implement query_ro, query_wo, and query_vco methods
    - Add WitnessOracle and VerificationOracle implementations

    - _Requirements: 2.5, 17.1, 17.2_
  
  - [ ] 3.4 Implement Signed Random Oracle Model
    - Create SignedOracle struct with signing oracle





    - Implement SigningOracle with sign method and transcript tracking
    - Add get_signing_queries method
    - _Requirements: 2.3, 15.3, 21.1, 21.2, 21.3_


- [ ] 4. Implement relativized SNARK interface
  - [ ] 4.1 Define RelativizedSNARK trait
    - Create trait with associated types for PublicParameters, IndexerKey, VerifierKey, Proof, Circuit, Statement, Witness





    - Define setup, index, prove, verify, and extract methods
    - Add oracle parameter to all methods requiring oracle access
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_
  

  - [ ] 4.2 Implement oracle forcing logic
    - Write force_oracle_queries method to query group elements
    - Implement compute_oracle_forcing_set to identify elements needing queries

    - Add serialize_group_element helper method
    - _Requirements: 7.4, 7.5, 7.6, 8.3, 8.4, 25.1, 25.2_

- [ ] 5. Implement incremental computation framework
  - [ ] 5.1 Create IncrementalComputation structure
    - Implement IncrementalComputation with function, depth_predicates, and size fields
    - Add apply method for F(z_{i-1}, w_i) → z_i
    - Implement check_depth and is_base_case methods
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_
  
  - [ ] 5.2 Implement DepthPredicates manager
    - Create DepthPredicates struct with HashMap of predicates
    - Add methods to register and query depth predicates
    - Implement well-foundedness checking
    - _Requirements: 5.2, 5.3, 5.4_

- [ ] 6. Implement IVC prover with AGM modifications
  - [x] 6.1 Create IVCProver structure

    - Implement IVCProver with ipk, pp, and group_parser fields
    - Add helper methods for statement and witness building
    - _Requirements: 6.3, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_
  

  - [x] 6.2 Implement prove_step method with oracle forcing

    - Write prove_step that simulates verifier to get tr_V
    - Extract group elements from (z_prev, π_prev)
    - Compute g = group(z_prev || π_prev) \ group(tr_V)
    - Force oracle queries for g and generate proof
    - _Requirements: 6.3, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_
  


  - [ ] 6.3 Add serialization helpers
    - Implement serialize_statement_proof method
    - Add extract_group_elements_from_transcript method
    - Write build_statement and build_witness helpers
    - _Requirements: 8.2, 8.3, 8.4, 8.5_

- [ ] 7. Implement IVC verifier
  - [x] 7.1 Create IVCVerifier structure

    - Implement IVCVerifier with ivk field
    - Add verify method handling base and recursive cases
    - _Requirements: 6.4, 9.1, 9.2, 9.3, 9.4_
  

  - [ ] 7.2 Implement verification logic
    - Check base case: z_0 = z_out
    - Check recursive case: verify SNARK proof
    - Add oracle forwarding
    - _Requirements: 6.4, 6.5, 6.6, 9.1, 9.2, 9.3, 9.4_

- [ ] 8. Implement IVC extractor with straight-line extraction
  - [x] 8.1 Create IVCExtractor structure

    - Implement IVCExtractor with pp and circuit fields
    - Add helper methods for parsing extracted witnesses
    - _Requirements: 6.7, 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9_
  

  - [ ] 8.2 Implement extract method
    - Write iterative extraction loop using single Γ
    - Extract witness for current step using SNARK extractor
    - Parse (w_loc, z_in, π_in, r_in) from extracted witness
    - Check base case and update for next iteration
    - Return complete witness chain
    - _Requirements: 6.7, 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9_
  

  - [ ] 8.3 Add witness parsing and validation
    - Implement parse_extracted_witness method
    - Add extract_z_out helper
    - Write is_base_case check
    - _Requirements: 10.3, 10.4, 10.5, 10.6_

- [ ] 9. Implement recursive verification circuit
  - [x] 9.1 Create RecursiveVerificationCircuit structure

    - Implement circuit with ivk, function, and depth_predicates fields
    - Add compute method for circuit evaluation
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_
  

  - [ ] 9.2 Implement circuit computation logic
    - Check function application: F(z_in, w_loc) = z_out
    - Handle base case: dpt^≤0(z_in) ⇒ z_in = z_0
    - Handle recursive case: verify previous proof
    - Implement oracle forcing check: θ(g) = r
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_
  
  - [x] 9.3 Add oracle forcing in circuit

    - Compute g = group(z_in || π_in) \ group(tr_V)
    - Verify oracle queries match r
    - Optimize for Fiat-Shamir case (g = ∅)
    - _Requirements: 7.4, 7.5, 7.6, 25.1_

- [ ] 10. Implement IVC security reduction
  - [x] 10.1 Create reduction adversary A^θ

    - Implement reduction that forwards oracle queries
    - Sample function F and invoke IVC adversary
    - Compute circuit index and run extractor
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8, 11.9_
  

  - [ ] 10.2 Implement extraction validation
    - Check validity of extracted witness
    - Verify circuit acceptance on extracted witness
    - Output SNARK adversary if validation fails
    - _Requirements: 11.5, 11.6, 11.7_
  
  - [x] 10.3 Add algebraic adversary construction


    - Parse Γ to obtain group representations
    - Build algebraic adversary for SNARK
    - Ensure inductive guarantee holds
    - _Requirements: 11.8, 11.9_

- [x] 11. Implement O-SNARK interface and O-AdPoK game




  - [ ] 11.1 Define OSNARK trait extending RelativizedSNARK
    - Add AuxiliaryInput associated type
    - Define extract_with_oracle method with oracle transcript parameter
    - _Requirements: 14.1, 14.4_

  
  - [ ] 11.2 Implement O-AdPoK game structure
    - Create OAdPoKGame with pp, oracle, and aux_oracle fields
    - Implement run method for game execution
    - Add adversary invocation with dual oracle access

    - _Requirements: 14.2, 14.3, 14.4, 14.5_
  
  - [x] 11.3 Add extraction with auxiliary oracle




    - Implement extract_with_oracle using signing oracle transcript
    - Check extraction success and witness validity
    - Return soundness violation detection result

    - _Requirements: 14.4, 14.5_

- [ ] 12. Implement aggregate signature construction
  - [ ] 12.1 Create AggregateSignature structure
    - Implement AggregateSignature with pp_snark, ipk, ivk, pp_sig fields
    - Add setup method computing SNARK and signature parameters
    - _Requirements: 13.1, 13.2, 13.3_

  
  - [ ] 12.2 Implement aggregate method
    - Build statement from (vk_i, m_i) pairs
    - Compute signature verifier transcript

    - Compute g = group(σ_i) \ group(tr_Σ)
    - Force oracle queries and build witness
    - Generate SNARK proof
    - _Requirements: 13.2, 13.5, 13.6_
  





  - [ ] 12.3 Implement verify method
    - Extract statement from public keys and messages

    - Verify SNARK proof
    - _Requirements: 13.3_
  
  - [x] 12.4 Add helper methods




    - Implement compute_signature_verifier_transcript
    - Add extract_group_elements for signatures
    - Write build_aggregate_witness

    - _Requirements: 13.2, 13.5, 13.6_

- [ ] 13. Implement aggregate verification circuit
  - [ ] 13.1 Create AggregateVerificationCircuit structure
    - Implement circuit with verify_signature function

    - Add compute method for circuit evaluation
    - _Requirements: 13.4, 13.5_
  
  - [ ] 13.2 Implement circuit computation
    - Check all signatures verify: vfy^θ(vk_i, m_i, σ_i) = 1

    - Compute oracle forcing set g
    - Verify oracle queries match r
    - _Requirements: 13.4, 13.5_





- [ ] 14. Implement aggregate signature security reduction
  - [ ] 14.1 Create EU-ACK game structure
    - Implement game allowing signing oracle queries

    - Add adversary output handling for forgery
    - _Requirements: 16.1_
  
  - [ ] 14.2 Implement reduction to EU-CMA
    - Create adversary B simulating aggregate signature game
    - Forward signing oracle queries to EU-CMA challenger

    - Run extractor on aggregate output
    - _Requirements: 16.2, 16.3, 16.4, 16.5_
  





  - [ ] 14.3 Add forgery identification and submission
    - Find forgery index i* where vk_i* = vk ∧ m_i* ∉ Q_σ
    - Derive group representation Γ* for σ_i*

    - Submit (m_i*, σ_i*, Γ*) to EU-CMA challenger
    - _Requirements: 16.6, 16.7, 16.8_
  
  - [ ] 14.4 Implement extractor failure analysis
    - Construct adversary C against O-AdPoK if extractor fails

    - Bound abort probability
    - _Requirements: 16.9_

- [x] 15. Implement PCD extension




  - [ ] 15.1 Create PCD data structures
    - Implement PCDTranscript with DAG structure
    - Create PCDVertex and PCDEdge structures

    - Add PCDProof structure
    - _Requirements: 12.1, 12.2_
  
  - [ ] 15.2 Implement PCD extractor with breadth-first traversal
    - Create PCDExtractor structure
    - Implement extract method with level-wise processing
    - Process all tuples in current level before moving to next
    - Reconstruct DAG from extracted vertices
    - _Requirements: 12.6, 12.7_
  
  - [ ] 15.3 Add PCD compliance checking
    - Implement compliance predicate verification
    - Check base case compliance: ϕ^θ(z_e, w_loc, (⊥)) = 1
    - Check recursive compliance: ϕ^θ(z_e, w_loc, (z)) = 1
    - _Requirements: 12.3, 12.4, 12.5_

- [ ] 16. Implement AROM emulation and security lifting
  - [ ] 16.1 Create AROMEmulator structure
    - Implement AROMEmulator with ro, witness_computer, vco_polynomial, and emulator_state
    - Add query_wo method computing wo(x) := B^ro(x, μ_x)
    - Implement query_vco for low-degree extension evaluation
    - _Requirements: 17.1, 17.2, 17.3_
  
  - [ ] 16.2 Implement security lifting
    - Create SecurityLifting structure with emulator
    - Implement lift_signature_security (Theorem 9)
    - Implement lift_osnark_security (Theorem 10)
    - _Requirements: 17.5, 17.6, 17.7_
  
  - [ ] 16.3 Add emulator state management
    - Implement EmulatorState with wo_cache and vco_cache
    - Add caching for witness and verification oracle queries
    - Implement verify_emulation for correctness checking
    - _Requirements: 17.3, 17.4_

- [ ] 17. Implement Groth16 instantiation with AGM modifications
  - [ ] 17.1 Create ModifiedGroth16 structure
    - Implement ModifiedGroth16 with proving_key, verifying_key, and group_parser
    - Add compute_groth16_proof method
    - _Requirements: 18.1, 18.2, 29.1, 29.2_
  
  - [ ] 17.2 Implement RelativizedSNARK trait for ModifiedGroth16
    - Implement prove method querying (A, B, C) to ROM
    - Implement verify method checking Groth16 verification and oracle response
    - Add serialize_abc helper method
    - _Requirements: 18.1, 18.2, 29.1, 29.2_

- [x] 18. Implement KZG with BLS signatures

  - [ ] 18.1 Create KZGWithBLS structure
    - Implement KZGWithBLS with kzg and bls fields
    - Add extract_with_bls method
    - _Requirements: 18.6, 20.1, 20.2, 20.3, 20.4_

  

  - [ ] 18.2 Implement extraction in presence of BLS signing oracle
    - Parse group representation: C = Σ γ_i · crs_i + Σ δ_j · σ_j
    - Check if any δ_j ≠ 0 (discrete log break)
    - Extract polynomial from γ coefficients
    - _Requirements: 20.1, 20.2, 20.3, 20.4_

- [ ] 19. Implement KZG with Schnorr signatures
  - [x] 19.1 Create KZGWithSchnorr structure


    - Implement KZGWithSchnorr with kzg and schnorr fields
    - Add extract_with_schnorr method
    - _Requirements: 18.7, 20.5, 20.6, 20.7, 20.8_
  


  - [ ] 19.2 Implement extraction with R_i substitution
    - Parse representation: C = Σ γ_i · crs_i + Σ δ_j · R_j
    - Implement substitute_r_dependencies: R_i = g^z_i · vk^(-e_i)
    - Check if vk coefficient is non-zero (discrete log break)
    - Extract polynomial from crs coefficients
    - _Requirements: 20.5, 20.6, 20.7, 20.8_






- [ ] 20. Implement signature scheme integration
  - [x] 20.1 Define signature scheme traits

    - Create SignatureScheme trait with setup, kg, sign, and vfy methods
    - Add oracle access to sign and vfy methods
    - _Requirements: 15.1, 15.2, 15.3, 15.4_
  

  - [x] 20.2 Implement AGM-aware signature wrapper

    - Create AGMSignatureScheme wrapping base scheme
    - Add group_representation_tracker field
    - Track group representations for all signature operations
    - _Requirements: 15.5, 15.6, 15.7_


- [ ] 21. Implement error handling and types
  - [ ] 21.1 Define error enums
    - Create ExtractionError with variants for all extraction failure modes

    - Create VerificationError for proof verification failures

    - Create SetupError for initialization failures
    - _Requirements: 31.1, 31.2, 31.3, 31.4, 31.5_
  
  - [ ] 21.2 Implement error conversion methods
    - Add to_security_reduction method for ExtractionError

    - Implement error propagation and context
    - _Requirements: 31.1, 31.2, 31.3_


- [ ] 22. Implement data models and serialization
  - [ ] 22.1 Define core data types
    - Implement IVCStatement, IVCWitness structures
    - Create AggregateStatement, AggregateWitness structures
    - Add Proof types (Groth16Proof, IVCProof, AggregateSignatureProof)
    - _Requirements: 22.1, 22.2, 22.3, 22.4, 22.5, 22.6_
  
  - [ ] 22.2 Implement serialization
    - Add serialize and deserialize methods for all data types
    - Implement efficient encoding for group and field elements
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [x] 23. Implement high-level APIs and builders

  - [x] 23.1 Create IVCBuilder API

    - Implement IVCBuilder with fluent interface
    - Add with_security_level method
    - Implement build method setting up IVC system
    - _Requirements: 6.1, 6.2, 6.3, 6.4_
  

  - [ ] 23.2 Create AggregateSignatureBuilder API
    - Implement AggregateSignatureBuilder with fluent interface
    - Add with_scheme method
    - Implement build method setting up aggregate signature system
    - _Requirements: 13.1, 13.2, 13.3_

  
  - [ ] 23.3 Add usage examples in documentation
    - Write example for IVC with Fibonacci computation
    - Add example for aggregate signature usage




    - Document integration with existing Neo components
    - _Requirements: 32.1, 32.2, 32.3, 32.4, 32.5_

- [ ] 24. Integrate with existing Neo codebase
  - [x] 24.1 Create adapter for Symphony SNARK

    - Implement SymphonyRelSNARK wrapping existing Symphony
    - Add oracle forcing logic to Symphony adapter
    - Implement RelativizedSNARK trait for adapter
    - _Requirements: 33.1, 33.2, 33.3, 33.4, 33.5_

  
  - [ ] 24.2 Extend existing hash oracle
    - Implement Oracle trait for existing HashOracle
    - Add transcript management to HashOracle
    - _Requirements: 33.3, 33.4_
  
  - [ ] 24.3 Add AGM configuration to NeoConfig
    - Create AGMConfig structure
    - Add agm field to NeoConfig
    - Implement default configuration
    - _Requirements: 40.1, 40.2, 40.3, 40.4, 40.5, 40.6, 40.7_

- [ ]* 25. Write unit tests for AGM components
  - Write tests for GroupRepresentation verification
  - Test AlgebraicAdversary interface
  - Test GroupParser extraction
  - _Requirements: 30.1, 30.2_

- [ ]* 26. Write unit tests for oracle components
  - Test RandomOracle consistency
  - Test AROM emulation correctness
  - Test SignedOracle transcript tracking
  - _Requirements: 30.2_

- [ ]* 27. Write unit tests for IVC components
  - Test IVC base case acceptance
  - Test IVC inductive case
  - Test IVC extractor correctness
  - _Requirements: 30.3, 30.4, 30.5_

- [ ]* 28. Write unit tests for aggregate signatures
  - Test signature aggregation
  - Test aggregate verification
  - Test security reduction
  - _Requirements: 30.6, 30.7_

- [ ]* 29. Write integration tests
  - Test AGM IVC with Symphony SNARK
  - Test aggregate signatures with existing signature schemes
  - Test PCD with DAG computations
  - _Requirements: 30.3, 30.4, 30.5, 30.6_

- [ ]* 30. Write property-based tests
  - Test group representation linearity
  - Test IVC correctness for arbitrary depth
  - Test oracle forcing completeness
  - _Requirements: 30.1, 30.2, 30.3, 30.4, 30.5_

- [ ]* 31. Add benchmarks
  - Benchmark IVC prover performance per step
  - Benchmark IVC verifier (constant time)
  - Benchmark extractor scaling with depth
  - Benchmark aggregate signature operations
  - _Requirements: 34.1, 34.2, 34.3, 34.4, 34.5_

- [ ]* 32. Write comprehensive documentation
  - Document AGM model and group representations
  - Document oracle access patterns
  - Document IVC recursive circuit structure
  - Document aggregate signature protocol
  - Document security proofs and reductions
  - _Requirements: 32.1, 32.2, 32.3, 32.4, 32.5_

---

## CRITICAL MISSING COMPONENTS (From Paper Analysis)

### Phase 1: AROM Emulation and Security Lifting (HIGHEST PRIORITY)

- [ ] 33. Implement AROM Emulator Core
  - [x] 33.1 Create AROMEmulator with stateful simulation


    - Implement AROMEmulator struct with ro, witness_computer, vco_polynomial, emulator_state
    - Add query_wo method that computes wo(x) := B^ro(x, μ_x) using only ro
    - Implement query_vco for low-degree extension evaluation
    - Add caching mechanism for wo and vco queries
    - _Requirements: 17.1, 17.2, 17.3, Paper Appendix E.2_
  
  - [ ] 33.2 Implement WitnessOracle computation
    - Create WitnessOracle struct that computes witnesses using random oracle
    - Implement B^ro(x, μ_x) computation algorithm
    - Add witness caching and consistency checking
    - _Requirements: 17.2, Paper Definition 14_
  
  - [ ] 33.3 Implement VerificationOracle with low-degree extension
    - Create VerificationOracle struct with polynomial representation
    - Implement low-degree extension of verification function (degree ≤ d)
    - Add polynomial evaluation at arbitrary points
    - Implement degree bound checking
    - _Requirements: 17.1, 17.2, Paper Definition 14_
  
  - [ ] 33.4 Add EmulatorState management
    - Implement EmulatorState with wo_cache and vco_cache
    - Add state persistence and restoration
    - Implement verify_emulation for correctness checking
    - Add statistics tracking for cache hits/misses
    - _Requirements: 17.3, 17.4, Paper Definition 16_

- [ ] 34. Implement Security Lifting Theorems
  - [ ] 34.1 Create SecurityLifting framework
    - Implement SecurityLifting struct with emulator
    - Add oracle augmentation support (O' that adds θ_ν+1 ← O(θ_1))
    - Implement reduction construction helpers
    - _Requirements: 17.4, 17.5, Paper Definition 17_
  
  - [ ] 34.2 Implement signature security lifting (Theorem 9)
    - Create lift_signature_security method
    - Implement reduction from AROM adversary to ROM adversary
    - Add emulator invocation in reduction
    - Prove EU-CMA in ROM implies EU-CMA in AROM
    - _Requirements: 17.6, Paper Theorem 9_
  
  - [ ] 34.3 Implement O-SNARK security lifting (Theorem 10)
    - Create lift_osnark_security method
    - Implement reduction from AROM O-AdPoK to ROM O-AdPoK
    - Add emulator state management in reduction
    - Prove O-AdPoK in ROM implies O-AdPoK in AROM
    - _Requirements: 17.7, Paper Theorem 10_
  
  - [ ] 34.4 Add generic security property preservation
    - Implement lift_security_property generic method
    - Add support for custom security games
    - Implement game transformation using emulator
    - _Requirements: 17.5, Paper Theorem 8_

### Phase 2: KZG Commitment Security with Signing Oracles

- [ ] 35. Implement KZG+BLS Security Analysis
  - [x] 35.1 Create KZGWithBLS extractor



    - Implement KZGWithBLS struct with kzg and bls fields
    - Add extract_with_bls method that handles signing oracle queries
    - Implement group representation parsing: C = Σ γ_i · crs_i + Σ δ_j · σ_j
    - _Requirements: 18.6, 20.1, 20.2, Paper Appendix D_
  
  - [x] 35.2 Implement BLS signature structure analysis


    - Create BLSSignatureAnalyzer for Q_σ containing (g_i, σ_i) where σ_i = g_i^sk
    - Implement coefficient extraction from signing oracle transcript
    - Add δ_j coefficient checking (non-zero implies discrete log break)
    - _Requirements: 20.3, Paper Appendix D_
  


  - [ ] 35.3 Add discrete log reduction for BLS
    - Implement discrete_log_reduction_bls method
    - Create adversary B that breaks discrete log if any δ_j ≠ 0
    - Add polynomial extraction from γ coefficients when all δ_j = 0
    - _Requirements: 20.4, Paper Appendix D_

  
  - [ ] 35.4 Implement KZG extraction with BLS oracle
    - Write extract_polynomial_with_bls method
    - Handle adversary with access to H: M → G_1 and signing oracle
    - Implement representation verification in terms of (crs, Q_σ)
    - _Requirements: 20.1, 20.2, 20.3, 20.4, Paper Appendix D_

- [ ] 36. Implement KZG+Schnorr Security Analysis
  - [x] 36.1 Create KZGWithSchnorr extractor

    - Implement KZGWithSchnorr struct with kzg and schnorr fields
    - Add extract_with_schnorr method
    - Implement representation parsing: C = Σ γ_i · crs_i + Σ δ_j · R_j
    - _Requirements: 18.7, 20.5, 20.6, Paper Appendix D_
  

  - [x] 36.2 Implement Schnorr signature structure analysis

    - Create SchnorrSignatureAnalyzer for Q_σ containing (R_i, z_i)
    - Verify R_i · vk^e_i · g^(-z_i) = 1 for all signatures
    - Implement R_i dependency tracking
    - _Requirements: 20.6, Paper Appendix D_
  
  - [x] 36.3 Add R_i substitution logic

    - Implement substitute_r_dependencies: R_i = g^z_i · vk^(-e_i)
    - Rewrite representation in terms of (g, vk) only
    - Check if vk coefficient is non-zero (discrete log break)
    - _Requirements: 20.7, Paper Appendix D_
  


  - [ ] 36.4 Add discrete log reduction for Schnorr
    - Implement discrete_log_reduction_schnorr method
    - Create adversary B that breaks discrete log if vk coefficient ≠ 0
    - Extract polynomial from crs coefficients when vk coefficient = 0
    - _Requirements: 20.8, Paper Appendix D_

### Phase 3: AHP to O-SNARK Compilation

- [ ] 37. Implement AHP Compiler Framework
  - [x] 37.1 Create AHP to O-SNARK compiler


    - Implement AHPCompiler struct with PCS and oracle support
    - Add compile method that takes AHP and PCS, outputs O-SNARK
    - Implement interactive argument construction
    - _Requirements: 19.1, Paper Theorem 7_

  
  - [ ] 37.2 Implement AHP prover compilation
    - Create compiled_prover that commits to polynomials p_i using PCS
    - Send commitments c_i in compiled proof
    - Add oracle query handling during commitment

    - _Requirements: 19.2, Paper Appendix D.1_
  
  - [ ] 37.3 Implement AHP verifier compilation
    - Create compiled_verifier that sends challenges ρ_i
    - Implement challenge generation using AHP verifier

    - Add verification of evaluation proofs
    - _Requirements: 19.3, Paper Appendix D.1_
  
  - [ ] 37.4 Add evaluation proof handling
    - Implement evaluation proof generation: π_i for p_i(z_i) = y_i
    - Output evaluations y_i with proofs

    - Add batch verification optimization
    - _Requirements: 19.4, Paper Appendix D.1_

- [ ] 38. Implement Fiat-Shamir Transformation
  - [x] 38.1 Add non-interactive transformation

    - Implement fiat_shamir_transform method
    - Make protocol non-interactive using random oracle
    - Add transcript hashing for challenge generation
    - _Requirements: 19.5, Paper Appendix D.1_
  

  - [ ] 38.2 Implement O-SNARK extraction from compiled AHP
    - Create extract_from_compiled method
    - Use PCS extractor to obtain polynomials from commitments
    - Handle signing oracle queries in extraction
    - _Requirements: 19.6, Paper Appendix D.1_

  
  - [ ] 38.3 Add KZG+BLS compilation verification
    - Verify extraction works with BLS signing oracle queries
    - Implement security reduction to KZG+BLS
    - Add test cases for BLS oracle interaction
    - _Requirements: 19.7, Paper Appendix D_
  
  - [ ] 38.4 Add KZG+Schnorr compilation verification
    - Verify extraction works with Schnorr signing oracle queries
    - Implement security reduction to KZG+Schnorr
    - Add test cases for Schnorr oracle interaction
    - _Requirements: 19.8, Paper Appendix D_

### Phase 4: Concrete SNARK Instantiations

- [ ] 39. Implement Modified Groth16
  - [ ] 39.1 Create ModifiedGroth16 structure
    - Implement ModifiedGroth16 with proving_key, verifying_key, group_parser
    - Add compute_groth16_proof method
    - Implement oracle forcing for (A, B, C)
    - _Requirements: 18.1, 18.2, Paper Section 2.1_
  
  - [ ] 39.2 Implement modified Groth16 prover
    - Write prove method that queries (A, B, C) to ROM
    - Output proof string (A, B, C, r) where r is oracle response
    - Add group element serialization
    - _Requirements: 18.1, Paper Section 2.1_
  
  - [ ] 39.3 Implement modified Groth16 verifier
    - Write verify method checking Groth16 verification
    - Verify oracle response correctness: θ(A, B, C) = r
    - Add pairing equation verification
    - _Requirements: 18.2, Paper Section 2.1_
  
  - [ ] 39.4 Implement RelativizedSNARK trait for ModifiedGroth16
    - Implement all trait methods with oracle access
    - Add extraction logic using AGM
    - Prove SLE in AGM+ROM
    - _Requirements: 18.1, 18.2, Paper Section 2.1_

- [ ] 40. Implement Marlin/Plonk/Sonic Instantiations
  - [ ] 40.1 Create PIOP+KZG compiler
    - Implement PIOPKZGCompiler for Marlin/Plonk/Sonic
    - Add polynomial commitment using KZG
    - Implement opening proof generation
    - _Requirements: 18.3, 18.4, 18.5, Paper Section 2.1_
  
  - [ ] 40.2 Add Marlin instantiation
    - Implement MarlinSNARK using PIOP+KZG
    - Add SLE in AGM+ROM proof
    - Implement RelativizedSNARK trait
    - _Requirements: 18.3, Paper Section 2.1_
  
  - [ ] 40.3 Add Plonk instantiation
    - Implement PlonkSNARK using PIOP+KZG
    - Add SLE in AGM+ROM proof
    - Implement RelativizedSNARK trait
    - _Requirements: 18.4, Paper Section 2.1_
  
  - [ ] 40.4 Add Sonic instantiation
    - Implement SonicSNARK using PIOP+KZG
    - Add SLE in AGM+ROM proof
    - Implement RelativizedSNARK trait
    - _Requirements: 18.5, Paper Section 2.1_

### Phase 5: PCD (Proof Carrying Data) Extension

- [ ] 41. Implement PCD Data Structures
  - [ ] 41.1 Create PCD DAG representation
    - Implement PCDTranscript with directed acyclic graph structure
    - Create PCDVertex with w_loc labels
    - Create PCDEdge with message labels
    - Add graph traversal utilities
    - _Requirements: 12.1, Paper Definition 6_
  
  - [ ] 41.2 Implement PCD output computation
    - Add compute_pcd_output method
    - Return message z_e where e = (u,v) is lexicographically-first edge to sink v
    - Implement sink vertex identification
    - _Requirements: 12.2, Paper Definition 6_
  
  - [ ] 41.3 Add PCDProof structure
    - Create PCDProof with proof per vertex
    - Implement proof aggregation for DAG
    - Add proof verification for entire DAG
    - _Requirements: 12.1, 12.2, Paper Appendix A_

- [x] 42. Implement PCD Extractor


  - [x] 42.1 Create PCDExtractor with breadth-first traversal


    - Implement PCDExtractor structure
    - Add extract method with level-wise processing
    - Store multiple (z_(i-1), π_(i-1)) tuples per level
    - _Requirements: 12.6, Paper Appendix A.1_
  

  - [x] 42.2 Implement level-wise extraction

    - Process all tuples in current level before moving to next
    - Invoke E on each tuple in list
    - Build witness DAG incrementally
    - _Requirements: 12.7, Paper Appendix A.1_

  


  - [ ] 42.3 Add DAG reconstruction
    - Reconstruct computation DAG from extracted vertices
    - Verify parent-child relationships
    - Check DAG acyclicity

    - _Requirements: 12.6, 12.7, Paper Appendix A.1_



- [ ] 43. Implement PCD Compliance Checking
  - [x] 43.1 Add compliance predicate verification

    - Implement verify_compliance method


    - Check ϕ^θ(z_e, w_loc, z) = 1 for each vertex
    - Add compliance predicate evaluation
    - _Requirements: 12.3, Paper Definition 8_

  

  - [ ] 43.2 Implement base case compliance
    - Check ϕ^θ(z_e, w_loc, (⊥)) = 1 for vertices with no incoming edges
    - Identify source vertices in DAG
    - Verify base case conditions
    - _Requirements: 12.4, Paper Definition 8_


  
  - [ ] 43.3 Implement recursive compliance
    - Check ϕ^θ(z_e, w_loc, (z)) = 1 where z = (z_e1, ..., z_eM) are incoming messages
    - Verify multi-parent vertex compliance
    - Handle message aggregation
    - _Requirements: 12.5, Paper Definition 8_

### Phase 6: Aggregate Signature Security Reduction


- [x] 44. Implement EU-ACK Game

  - [x] 44.1 Create EU-ACK game structure

    - Implement EUACKGame with signing oracle
    - Allow adversary to query signing oracle
    - Add forgery output handling for one of n public keys
    - _Requirements: 16.1, Paper Definition 13_
  

  - [ ] 44.2 Add adversary interface for EU-ACK
    - Define EUACKAdversary trait
    - Implement run method with signing oracle access
    - Add forgery verification



    - _Requirements: 16.1, Paper Definition 13_

- [ ] 45. Implement Aggregate Signature Security Reduction
  - [ ] 45.1 Create reduction to EU-CMA (Game G0)
    - Implement adversary B that simulates aggregate signature game for A

    - Forward signing oracle queries to EU-CMA challenger
    - Return responses to A
    - _Requirements: 16.2, 16.3, 16.4, Paper Theorem 5 proof_
  
  - [x] 45.2 Implement extractor invocation (Game G1)

    - Run extractor E on A's output: ({vk_i, m_i}_i∈[n], σ_agg)
    - Extract (σ_1, ..., σ_n, r) from aggregate signature
    - Handle extractor failure (abort event)
    - _Requirements: 16.5, Paper Theorem 5 proof_
  

  - [ ] 45.3 Add forgery identification
    - Find forgery index i* where vk_i* = vk ∧ m_i* ∉ Q_σ
    - Verify extracted signature σ_i* is valid
    - Check forgery conditions
    - _Requirements: 16.6, Paper Theorem 5 proof_

  
  - [ ] 45.4 Implement group representation derivation
    - Derive Γ* for σ_i* in terms of (pp_Σ, vk, Q_σ)
    - Parse Γ from A's output




    - Recompute representation for single signature
    - _Requirements: 16.7, Paper Theorem 5 proof_
  
  - [ ] 45.5 Add forgery submission
    - Submit (m_i*, σ_i*, Γ*) to EU-CMA challenger

    - Verify forgery is valid
    - Complete reduction
    - _Requirements: 16.8, Paper Theorem 5 proof_

- [ ] 46. Implement Extractor Failure Analysis
  - [ ] 46.1 Create adversary C against O-AdPoK
    - Construct C that runs A internally
    - Simulate aggregate signature game
    - Output when extractor fails
    - _Requirements: 16.9, Paper Theorem 5 proof_
  
  - [ ] 46.2 Bound abort probability
    - Prove |Pr[G0(A)] - Pr[G1(A)]| ≤ Pr[O-AdPoK(C)]
    - Show extractor failure implies O-AdPoK break
    - Complete security proof
    - _Requirements: 16.9, Paper Theorem 5 proof_

### Phase 7: Auxiliary Input and Oracle Families

- [x] 47. Implement Auxiliary Input Distribution






  - [ ] 47.1 Create Z_Σ distribution
    - Implement Z_Σ that samples pp_Σ
    - Generate (vk, sk) ← KGen(pp_Σ)
    - Output (aux := vk, st := sk)
    - _Requirements: 21.1, Paper Figure 6_
  


  - [ ] 47.2 Implement O_sk signing oracle
    - Create O_sk oracle that computes σ ← sign^θ(sk, m)
    - Add transcript tracking for signing queries
    - Return signatures to adversary
    - _Requirements: 21.2, Paper Figure 6_


  
  - [ ] 47.3 Add Z-auxiliary input to O-AdPoK
    - Modify O-AdPoK game to sample aux ← Z(1^λ)
    - Provide aux to adversary
    - Pass aux to extractor



    - _Requirements: 21.3, Paper Definition 5_

### Phase 8: Oracle Forcing Optimization

- [x] 48. Implement Fiat-Shamir Optimization




  - [ ] 48.1 Add Fiat-Shamir detection
    - Detect when verifier queries entire (statement, proof) to oracle
    - Identify Fiat-Shamir transformed SNARKs




    - Set g = ∅ for these cases
    - _Requirements: 8.6, Paper Section 2.1 efficiency note_

  

  - [ ] 48.2 Implement zero-overhead oracle forcing
    - Skip oracle forcing when g = ∅
    - Optimize prover for Fiat-Shamir case
    - Add performance benchmarks





    - _Requirements: 8.6, Paper Section 2.1 efficiency note_







### Phase 9: Integration and Testing


- [ ] 49. Complete Missing Oracle Implementations
  - [x] 49.1 Finish Random Oracle Model (ROM)

    - Complete RandomOracle struct with ChaCha20Rng
    - Implement Oracle trait with caching
    - Add query method with transcript recording

    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  
  - [ ] 49.2 Finish Signed Random Oracle Model
    - Complete SignedOracle struct
    - Implement SigningOracle with sign method
    - Add get_signing_queries method
    - _Requirements: 2.3, 15.3, 21.1, 21.2, 21.3_

- [ ] 50. Complete Missing Core Components
  - [ ] 50.1 Finish RelativizedSNARK trait definition
    - Complete trait with all associated types
    - Define all required methods
    - Add oracle parameters
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_
  
  - [ ] 50.2 Finish incremental computation framework
    - Complete IncrementalComputation structure
    - Implement DepthPredicates manager
    - Add well-foundedness checking
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_
  
  - [ ] 50.3 Complete IVC implementation
    - Finish IVC prover serialization helpers
    - Complete IVC verifier logic
    - Finish IVC extractor methods
    - Complete recursive circuit computation
    - _Requirements: 6.3, 7.2, 8.2, 8.3, 9.2_
  
  - [ ] 50.4 Complete aggregate signature implementation
    - Finish AggregateSignature structure
    - Complete aggregate and verify methods
    - Finish aggregate verification circuit
    - _Requirements: 12.1, 12.2, 12.3, 13.1, 13.2_

- [ ]* 51. Integration Testing for New Components
  - Test AROM emulation with real SNARKs
  - Test KZG+BLS/Schnorr extraction
  - Test AHP compilation to O-SNARK
  - Test modified Groth16 with oracle forcing
  - Test PCD with DAG computations
  - Test aggregate signature security reduction
  - _Requirements: All new components_

- [ ]* 52. Performance Benchmarking
  - Benchmark AROM emulation overhead
  - Benchmark KZG extraction with signing oracles
  - Benchmark AHP compilation
  - Benchmark modified Groth16
  - Benchmark PCD extraction
  - Compare with paper's theoretical bounds
  - _Requirements: All new components_

---

## Notes

- Tasks marked with `*` are optional testing and documentation tasks that can be skipped for MVP
- **CRITICAL MISSING COMPONENTS** section contains all implementations identified from paper analysis
- Each task builds incrementally on previous tasks
- All tasks reference specific requirements from the requirements document
- The implementation follows a bottom-up approach: primitives → protocols → applications
- Integration with existing Neo codebase is designed to be non-breaking
- Testing strategy emphasizes correctness of core extraction and security properties
- **Priority Order**: Phase 1 (AROM) → Phase 2 (KZG) → Phase 3 (AHP) → Phase 4 (Concrete SNARKs) → Phase 5 (PCD) → Phase 6 (Aggregate Sig Security) → Phase 7 (Auxiliary Input) → Phase 8 (Optimization) → Phase 9 (Integration)
