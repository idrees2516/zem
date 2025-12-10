# Requirements Document: AGM-Secure Functionalities with Cryptographic Proofs

## Introduction

This document provides comprehensive requirements for implementing the AGM-Secure Functionalities framework for composing cryptographic proofs with AGM-secure primitives, enabling unbounded-depth IVC and aggregate signatures.

## Glossary

- **AGM (Algebraic Group Model)**: A security model where adversaries must provide group representations for all group elements they output
- **IVC (Incrementally Verifiable Computation)**: A cryptographic primitive allowing incremental proof generation for long computations
- **rel-SNARK**: Relativized SNARK that can prove computations involving oracle calls
- **SLE (Straight-Line Extractable)**: Property where an extractor can extract witnesses without rewinding
- **AROM (Arithmetized Random Oracle Model)**: Oracle model allowing succinct proofs about oracle queries
- **O-SNARK**: SNARK with extraction in the presence of additional oracles (e.g., signing oracles)
- **PCD (Proof Carrying Data)**: Generalization of IVC to directed acyclic graph computations
- **Group Representation**: Vector of coefficients explaining a group element as linear combination of basis elements
- **Oracle Transcript**: List of (query, response) pairs from oracle interactions
- **Knowledge Soundness**: Property ensuring valid witness extraction from accepting proofs
- **Succinctness**: Property where verification time is sublinear in computation size

---

## Requirements

### Requirement 1: Core AGM Infrastructure

**User Story:** As a cryptographer, I want to implement the extended Algebraic Group Model with oracle support, so that I can reason about security of composed primitives.

#### Acceptance Criteria

1.1 **WHEN** an algebraic adversary outputs group elements, **THE System** **SHALL** require group representations for all output elements
   - _Requirements: Mathematical foundation for AGM security_

1.2 **WHEN** an algebraic adversary queries an oracle with group elements, **THE System** **SHALL** require group representations for queried elements in the oracle transcript
   - _Requirements: Extended AGM model from Section 3.1_

1.3 **WHEN** group representations are provided, **THE System** **SHALL** verify that y||y^θ = Γ^T x where y are output elements, y^θ are oracle-queried elements, and x are received elements
   - _Requirements: Algebraic constraint verification_

1.4 **WHERE** bilinear groups are used, **THE System** **SHALL** support group representations in both G1 and G2
   - _Requirements: Pairing-based cryptography support_

1.5 **WHEN** oblivious sampling occurs, **THE System** **SHALL** track group elements obtained through sampling
   - _Requirements: AGMOS compatibility from [LPS23]_


### Requirement 2: Oracle Distribution and Transcript Management

**User Story:** As a protocol designer, I want comprehensive oracle management, so that I can track all oracle interactions for security proofs.

#### Acceptance Criteria

2.1 **WHEN** an oracle distribution O_λ is sampled, **THE System** **SHALL** generate oracle θ: X → Y for specified domain X and codomain Y
   - _Requirements: Oracle distribution framework from Section 3_

2.2 **WHEN** an algorithm A^θ makes oracle queries, **THE System** **SHALL** maintain transcript tr_A containing all (query, response) pairs
   - _Requirements: Oracle transcript tracking_

2.3 **WHEN** multiple oracle types are used, **THE System** **SHALL** support ROM, AROM, Signed ROM, and custom oracle models
   - _Requirements: Multi-oracle model support_

2.4 **WHEN** oracle responses are generated, **THE System** **SHALL** ensure consistency across repeated queries
   - _Requirements: Oracle consistency property_

2.5 **WHERE** AROM is used, **THE System** **SHALL** provide interfaces (ro, wo, vco) for random oracle, witness oracle, and verification oracle
   - _Requirements: AROM structure from Definition 14_

### Requirement 3: Relativized SNARK Implementation

**User Story:** As a SNARK developer, I want to implement relativized SNARKs with AGM security, so that I can build secure IVC systems.

#### Acceptance Criteria

3.1 **WHEN** generating public parameters, **THE System** **SHALL** implement G(1^λ) → pp
   - _Requirements: Setup algorithm from Definition 1_

3.2 **WHEN** indexing a circuit, **THE System** **SHALL** implement I^θ(i, pp) → (ipk, ivk) with oracle access
   - _Requirements: Indexing with oracle support_

3.3 **WHEN** proving a statement, **THE System** **SHALL** implement P^θ(ipk, x, w) → π with oracle access
   - _Requirements: Prover algorithm_

3.4 **WHEN** verifying a proof, **THE System** **SHALL** implement V^θ(ivk, x, π) → ⊤/⊥ with oracle access
   - _Requirements: Verifier algorithm_

3.5 **WHEN** completeness is checked, **THE System** **SHALL** ensure Pr[(i,x,w) ∈ R^θ ⇒ V^θ(ivk,x,π) = ⊤] = 1
   - _Requirements: Completeness property_

3.6 **WHEN** knowledge soundness is checked, **THE System** **SHALL** provide extractor E such that Pr[V^θ(ivk,x,π) = ⊤ ∧ (i,x,w) ∉ R^θ] ≤ negl(λ)
   - _Requirements: SLE in AGM+O from Definition 1_

3.7 **WHEN** verifying succinctness, **THE System** **SHALL** ensure verifier runtime is poly(λ + |x|) independent of |i|
   - _Requirements: Succinctness property_


### Requirement 4: Group Element Parsing and Management

**User Story:** As a system architect, I want robust group element parsing, so that I can correctly extract and track group elements in mixed data structures.

#### Acceptance Criteria

4.1 **WHEN** parsing output lst ∈ G^ℓ_G × F^ℓ_F, **THE System** **SHALL** implement group(lst) to extract ℓ_G group elements
   - _Requirements: Group parsing from Section 3.2_

4.2 **WHEN** group elements are sorted, **THE System** **SHALL** maintain publicly known ordering for consistent extraction
   - _Requirements: Deterministic ordering_

4.3 **WHEN** circuits use group elements, **THE System** **SHALL** support wires labeled with group elements and gates performing group operations
   - _Requirements: Group-aware circuit representation_

4.4 **WHEN** extracting witnesses, **THE System** **SHALL** return group elements in the correct format without requiring special encoding
   - _Requirements: Natural group element handling_

4.5 **WHERE** field elements and group elements are mixed, **THE System** **SHALL** distinguish them without ambiguity
   - _Requirements: Type safety for mixed structures_

### Requirement 5: Function Samplers and Incremental Computation

**User Story:** As a computation designer, I want to define incremental computations with proper depth tracking, so that I can build IVC for arbitrary-depth chains.

#### Acceptance Criteria

5.1 **WHEN** sampling a function, **THE System** **SHALL** implement F(1^λ) → F where F: {0,1}^n_in × {0,1}^n_w → {0,1}^n_out
   - _Requirements: Function sampler from Definition 2_

5.2 **WHEN** defining incremental computation, **THE System** **SHALL** provide (F, dpt^≤) where dpt^≤ is depth predicate family
   - _Requirements: Incremental computation from Definition 3_

5.3 **WHEN** checking depth predicates, **THE System** **SHALL** ensure dpt^≤_D_F(z') = ⊤ ∧ z→^F_w z' ⇒ dpt^≤_(D-1)_F(z) = ⊤
   - _Requirements: Well-founded depth relation_

5.4 **WHEN** identifying base cases, **THE System** **SHALL** test dpt^≤0_F(z) to determine source nodes
   - _Requirements: Base case detection_

5.5 **WHERE** depth is encoded in output, **THE System** **SHALL** support both explicit depth d and short encodings like H(d)
   - _Requirements: Flexible depth encoding from Remark 5_


### Requirement 6: IVC Core Algorithms

**User Story:** As an IVC implementer, I want complete IVC algorithms with AGM-aware modifications, so that I can achieve unbounded-depth security.

#### Acceptance Criteria

6.1 **WHEN** generating IVC parameters, **THE System** **SHALL** implement G^θ(1^λ) → pp
   - _Requirements: IVC setup from Definition 4_

6.2 **WHEN** indexing IVC function, **THE System** **SHALL** implement I^θ(pp, F) → (ipk, ivk)
   - _Requirements: IVC indexing_

6.3 **WHEN** proving IVC step, **THE System** **SHALL** implement P^θ(ipk, z_0, z_i, (w_i, z_(i-1), π_(i-1))) → π_i
   - _Requirements: Incremental prover_

6.4 **WHEN** verifying IVC proof, **THE System** **SHALL** implement V^θ(ivk, z_0, z_out, π_out) → ⊤/⊥
   - _Requirements: IVC verifier_

6.5 **WHEN** checking base case correctness, **THE System** **SHALL** ensure dpt^≤0_F(z_0) = ⊤ ⇒ V^θ(ivk, z_0, z_0, ⊥) = ⊤
   - _Requirements: Base case correctness_

6.6 **WHEN** checking inductive correctness, **THE System** **SHALL** ensure F(z_(i-1), w_i) = z_i ∧ V^θ(ivk, z_0, z_(i-1), π_(i-1)) = ⊤ ⇒ V^θ(ivk, z_0, z_i, π_i) = ⊤
   - _Requirements: Inductive correctness_

6.7 **WHEN** checking unbounded-depth knowledge soundness, **THE System** **SHALL** provide extractor Ext such that for any poly-bounded depth d(λ), Pr[V^θ accepts ∧ ∃i: F(z_(i-1), w_i) ≠ z_i] ≤ negl(λ)
   - _Requirements: Unbounded-depth security from Definition 4_

6.8 **WHEN** verifying succinctness, **THE System** **SHALL** ensure verifier runtime is poly(λ + |x|) independent of |F| and depth
   - _Requirements: IVC succinctness_

### Requirement 7: Recursive Circuit Construction

**User Story:** As a circuit designer, I want to build the recursive verification circuit with AGM modifications, so that extraction works correctly.

#### Acceptance Criteria

7.1 **WHEN** constructing recursive circuit [CV_λ]^θ, **THE System** **SHALL** check F(w_loc, z_in) = z_out
   - _Requirements: Function application check from Section 4.2_

7.2 **WHEN** checking base case in circuit, **THE System** **SHALL** verify dpt^≤0_F(z_in) = ⊤ ⇒ z_in = z_0
   - _Requirements: Base case verification_

7.3 **WHEN** checking recursive case in circuit, **THE System** **SHALL** verify V^θ(ivk, (ivk, z_0, z_in), π_in) = 1
   - _Requirements: Recursive verification_

7.4 **WHEN** forcing oracle queries in circuit, **THE System** **SHALL** check θ(g) = r where g = group(z_in || π_in) \ group(tr_V)
   - _Requirements: AGM-specific oracle forcing from highlighted modification_

7.5 **WHERE** verifier already queries group elements, **THE System** **SHALL** only force queries for remaining elements not in tr_V
   - _Requirements: Optimization from efficiency note_

7.6 **WHEN** w_loc is used, **THE System** **SHALL** NOT require oracle queries for w_loc since it's not needed for extraction
   - _Requirements: Selective oracle forcing_


### Requirement 8: IVC Prover Algorithm with AGM Modifications

**User Story:** As a prover implementer, I want the complete IVC prover with oracle forcing, so that the AGM extractor can work correctly.

#### Acceptance Criteria

8.1 **WHEN** forwarding oracle queries, **THE System** **SHALL** relay all queries from underlying algorithms to θ and return responses
   - _Requirements: Oracle forwarding from Fig. 1_

8.2 **WHEN** computing verifier transcript, **THE System** **SHALL** run V^θ(pp, (pp, z_0, z_(i-1)), π_(i-1)) to obtain tr_V
   - _Requirements: Verifier simulation_

8.3 **WHEN** identifying group elements to query, **THE System** **SHALL** compute g = group(z_(i-1) || π_(i-1)) \ group(tr_V)
   - _Requirements: Group element identification_

8.4 **WHEN** forcing oracle queries, **THE System** **SHALL** query θ(g) to obtain r
   - _Requirements: Oracle forcing_

8.5 **WHEN** generating proof, **THE System** **SHALL** run π_i ← P^θ(ipk, (ivk, z_0, z_i); w_i, z_(i-1), π_(i-1), r)
   - _Requirements: Proof generation with oracle responses_

8.6 **WHERE** Fiat-Shamir is used, **THE System** **SHALL** have g = ∅ since verifier queries entire (statement, proof)
   - _Requirements: Fiat-Shamir optimization_

### Requirement 9: IVC Verifier Algorithm

**User Story:** As a verifier implementer, I want the IVC verifier that handles base and recursive cases, so that proofs can be validated efficiently.

#### Acceptance Criteria

9.1 **WHEN** forwarding oracle queries, **THE System** **SHALL** relay all queries from underlying algorithms to θ
   - _Requirements: Oracle forwarding_

9.2 **WHEN** checking base case, **THE System** **SHALL** set b = 1 if z_0 = z_out
   - _Requirements: Base case acceptance_

9.3 **WHEN** checking recursive case, **THE System** **SHALL** run b ← V^θ(ivk, (ivk, z_out), π_out)
   - _Requirements: Recursive verification_

9.4 **WHEN** outputting decision, **THE System** **SHALL** return b
   - _Requirements: Decision output_


### Requirement 10: IVC Extractor Algorithm

**User Story:** As a security analyst, I want the IVC extractor that works in straight-line without exponential blowup, so that I can prove knowledge soundness.

#### Acceptance Criteria

10.1 **WHEN** initializing extractor, **THE System** **SHALL** create empty list L and compute circuit index i for CV_λ
   - _Requirements: Extractor initialization from Fig. 2_

10.2 **WHEN** setting initial statement, **THE System** **SHALL** initialize x_out = (pp, z_0, z_out) and isLast = 0
   - _Requirements: Statement initialization_

10.3 **WHILE** isLast = 0, **THE System** **SHALL** run (w_loc, z_in, π_in, r^in) ← E(pp, i, x_out, π_out, tr_P̃, Γ)
   - _Requirements: Iterative extraction_

10.4 **WHEN** extraction succeeds, **THE System** **SHALL** add pair (w_loc, z_out) to L
   - _Requirements: Witness accumulation_

10.5 **WHEN** base case is reached, **THE System** **SHALL** check dpt^≤0_F(z_in) = ⊤ and update isLast = 1
   - _Requirements: Base case detection_

10.6 **WHEN** continuing extraction, **THE System** **SHALL** redefine x_out = (pp, z_0, z_in) and π_out = π_in
   - _Requirements: State update for next iteration_

10.7 **WHEN** extraction completes, **THE System** **SHALL** output L containing all (w_i, z_i) pairs
   - _Requirements: Complete witness chain output_

10.8 **WHEN** using group representations, **THE System** **SHALL** use single Γ from initial adversary output for all iterations
   - _Requirements: Avoiding exponential blowup from Section 2.1_

10.9 **WHERE** group elements appear in oracle transcript, **THE System** **SHALL** find representations by parsing Γ
   - _Requirements: Transcript-based representation extraction_

### Requirement 11: Knowledge Soundness Reduction

**User Story:** As a proof theorist, I want the reduction from IVC adversary to SNARK adversary, so that I can prove security formally.

#### Acceptance Criteria

11.1 **WHEN** building reduction A^θ(pp), **THE System** **SHALL** forward all oracle queries between subroutines
   - _Requirements: Reduction algorithm from Fig. 3_

11.2 **WHEN** sampling function, **THE System** **SHALL** run F ← F(λ)
   - _Requirements: Function sampling_

11.3 **WHEN** invoking adversary, **THE System** **SHALL** run P̃ on (pp, F) to receive (z_0, z_out, π_out, Γ)
   - _Requirements: Adversary invocation_

11.4 **WHEN** computing circuit index, **THE System** **SHALL** compute index i for CV_λ and (ipk, ivk) ← I^θ(i, pp)
   - _Requirements: Circuit indexing_

11.5 **WHEN** iterating extraction, **THE System** **SHALL** run E and check validity of extracted witness
   - _Requirements: Extraction with validation_

11.6 **WHEN** check fails, **THE System** **SHALL** verify [CV_λ]^θ(ivk, z_0, z_out; w_loc, z_in, π_in, r^in) = 1
   - _Requirements: Witness validation_

11.7 **IF** validation fails (b = 1), **THE System** **SHALL** output (i, (ivk, z_0, z_out), π_out) as SNARK adversary
   - _Requirements: Bad event handling_

11.8 **WHEN** building algebraic adversary, **THE System** **SHALL** parse Γ to obtain group representations for (z_i, π_i, tr_V)
   - _Requirements: Algebraic adversary construction_

11.9 **WHERE** circuit accepts in iteration i-1, **THE System** **SHALL** guarantee group elements in (z_in, π_in) are in tr_P̃
   - _Requirements: Inductive guarantee from proof_


### Requirement 12: PCD Extension

**User Story:** As a distributed computation designer, I want PCD support for DAG computations, so that I can handle parallel computation trees.

#### Acceptance Criteria

12.1 **WHEN** defining PCD transcript, **THE System** **SHALL** represent computation as directed acyclic graph with vertices labeled by w_loc and edges labeled by messages
   - _Requirements: PCD transcript from Definition 6_

12.2 **WHEN** computing PCD output, **THE System** **SHALL** return message z_e where e = (u,v) is lexicographically-first edge to sink v
   - _Requirements: Output definition_

12.3 **WHEN** checking compliance predicate, **THE System** **SHALL** verify ϕ^θ(z_e, w_loc, z) = 1 for each vertex
   - _Requirements: Compliance from Definition 8_

12.4 **WHEN** checking base case compliance, **THE System** **SHALL** verify ϕ^θ(z_e, w_loc, (⊥)) = 1 for vertices with no incoming edges
   - _Requirements: Base case compliance_

12.5 **WHEN** checking recursive compliance, **THE System** **SHALL** verify ϕ^θ(z_e, w_loc, (z)) = 1 where z = (z_e1, ..., z_eM) are incoming messages
   - _Requirements: Recursive compliance_

12.6 **WHEN** extracting PCD witnesses, **THE System** **SHALL** use breadth-first extraction storing multiple (z_(i-1), π_(i-1)) tuples per level
   - _Requirements: PCD extractor from Appendix A.1_

12.7 **WHEN** processing PCD level, **THE System** **SHALL** invoke E on each tuple in list before moving to next level
   - _Requirements: Level-wise extraction_

### Requirement 13: Aggregate Signature Construction

**User Story:** As a signature aggregator, I want to build aggregate signatures from AGM-secure signatures and SNARKs, so that I can compress multiple signatures.

#### Acceptance Criteria

13.1 **WHEN** setting up aggregate signature, **THE System** **SHALL** implement AggSetup^θ(1^λ) computing pp_Π, (ipk, ivk), pp_Σ
   - _Requirements: Aggregate setup from Section 5.2_

13.2 **WHEN** aggregating signatures, **THE System** **SHALL** implement AggSign^θ(pp, {vk_i, m_i, σ_i}_i∈[n]) → σ_agg
   - _Requirements: Aggregation algorithm_

13.3 **WHEN** verifying aggregate, **THE System** **SHALL** implement AggVer(pp, {vk_i, m_i}_i∈[n], σ_agg) → b
   - _Requirements: Aggregate verification_

13.4 **WHEN** building verification circuit, **THE System** **SHALL** check vfy^θ(vk_i, m_i, σ_i) = 1 for all i ∈ [n]
   - _Requirements: Circuit from Fig. 5_

13.5 **WHEN** forcing oracle queries in aggregate, **THE System** **SHALL** check θ(g) = r where g = group(σ_i)_i∈[n] \ group(tr_Σ)
   - _Requirements: AGM forcing for signatures_

13.6 **WHEN** computing aggregate proof, **THE System** **SHALL** run σ_agg ← P^θ(ipk, x; w) where x = (vk_i, m_i)_i∈[n] and w = ((σ_i)_i∈[n], r)
   - _Requirements: SNARK proof generation_


### Requirement 14: O-SNARK Implementation

**User Story:** As a SNARK developer, I want O-SNARKs with extraction in presence of signing oracles, so that aggregate signatures are provably secure.

#### Acceptance Criteria

14.1 **WHEN** defining O-SNARK, **THE System** **SHALL** extend rel-SNARK with adaptive proof of knowledge O-AdPoK
   - _Requirements: O-SNARK from Definition 5_

14.2 **WHEN** running O-AdPoK game, **THE System** **SHALL** sample θ ← O(1^λ), (aux, st) ← Z(1^λ, θ), O_st ← O(st, θ)
   - _Requirements: O-AdPoK setup from Fig. 4_

14.3 **WHEN** adversary runs, **THE System** **SHALL** provide access to both O and θ oracles
   - _Requirements: Dual oracle access_

14.4 **WHEN** extracting in O-AdPoK, **THE System** **SHALL** run w ← E(pp, i, aux, x, π, Q, tr_A, Γ) where Q contains signing oracle queries
   - _Requirements: Extraction with oracle transcript_

14.5 **WHEN** checking O-AdPoK success, **THE System** **SHALL** return 1 if V^θ(ivk, y, π) = 1 ∧ (y, w) ∉ R^θ
   - _Requirements: Soundness violation detection_

14.6 **WHERE** KZG commitment is used, **THE System** **SHALL** support extraction in presence of BLS and Schnorr signing oracles
   - _Requirements: KZG+BLS/Schnorr from Appendix D_

### Requirement 15: Signature Scheme Integration

**User Story:** As a signature scheme developer, I want AGM-secure signatures with oracle support, so that they can be used in aggregate constructions.

#### Acceptance Criteria

15.1 **WHEN** setting up signature scheme, **THE System** **SHALL** implement setup(1^λ) → pp_Σ
   - _Requirements: Signature setup from Appendix B_

15.2 **WHEN** generating keys, **THE System** **SHALL** implement kg(pp_Σ) → (sk, vk)
   - _Requirements: Key generation_

15.3 **WHEN** signing messages, **THE System** **SHALL** implement sign^θ(sk, m) → σ with oracle access
   - _Requirements: Signing with oracle_

15.4 **WHEN** verifying signatures, **THE System** **SHALL** implement vfy^θ(vk, m, σ) → b with oracle access
   - _Requirements: Verification with oracle_

15.5 **WHEN** checking correctness, **THE System** **SHALL** ensure Pr[vfy^θ(vk, m, σ) = 1] = 1 - negl(λ) for honestly generated signatures
   - _Requirements: Correctness from Definition 10_

15.6 **WHEN** checking EU-CMA security, **THE System** **SHALL** ensure Pr[EU-CMA_Σ(A, λ) = 1] ≤ negl(λ) for algebraic adversaries
   - _Requirements: Unforgeability from Definition 11_

15.7 **WHEN** adversary outputs forgery, **THE System** **SHALL** require group representation Γ for σ* in terms of (pp_Σ, vk, Q_σ)
   - _Requirements: Algebraic forgery requirement_


### Requirement 16: Aggregate Signature Security Proof

**User Story:** As a security researcher, I want the complete security reduction for aggregate signatures, so that I can prove unforgeability.

#### Acceptance Criteria

16.1 **WHEN** defining EU-ACK game, **THE System** **SHALL** allow adversary to query signing oracle and output forgery for one of n public keys
   - _Requirements: EU-ACK from Definition 13_

16.2 **WHEN** building reduction to EU-CMA, **THE System** **SHALL** construct adversary B that simulates aggregate signature game for A
   - _Requirements: Reduction from Theorem 5 proof_

16.3 **WHEN** B receives (pp_Σ, vk), **THE System** **SHALL** locally compute pp_Π, (ipk, ivk) and set pp, aux
   - _Requirements: Setup simulation_

16.4 **WHEN** A queries O_Sign, **THE System** **SHALL** forward to EU-CMA challenger and return response
   - _Requirements: Oracle forwarding_

16.5 **WHEN** A outputs ({vk_i, m_i}_i∈[n], σ_agg), **THE System** **SHALL** run extractor E to obtain (σ_1, ..., σ_n, r)
   - _Requirements: Signature extraction_

16.6 **WHEN** finding forgery index i*, **THE System** **SHALL** identify i* where vk_i* = vk ∧ m_i* ∉ Q_σ
   - _Requirements: Forgery identification_

16.7 **WHEN** computing group representation, **THE System** **SHALL** derive Γ* for σ_i* in terms of (pp_Σ, vk, Q_σ)
   - _Requirements: Representation derivation_

16.8 **WHEN** submitting forgery, **THE System** **SHALL** output (m_i*, σ_i*, Γ*) to EU-CMA challenger
   - _Requirements: Forgery submission_

16.9 **WHEN** bounding abort probability, **THE System** **SHALL** construct adversary C against O-AdPoK if extractor fails
   - _Requirements: Extractor failure analysis_

### Requirement 17: AROM Emulation and Lifting

**User Story:** As a protocol designer, I want to lift ROM-secure primitives to AROM, so that I can use them in relativized settings.

#### Acceptance Criteria

17.1 **WHEN** defining AROM, **THE System** **SHALL** provide (ro, wo, vco) where vco is low-degree extension of verification function
   - _Requirements: AROM from Definition 14_

17.2 **WHEN** sampling AROM, **THE System** **SHALL** sample ro uniformly, compute wo(x) := B^ro(x, μ_x), and sample vco from degree-d extensions
   - _Requirements: AROM sampling_

17.3 **WHEN** emulating AROM, **THE System** **SHALL** implement stateful (O, S)-emulator M that simulates (wo, vco) using only ro
   - _Requirements: Emulator from Definition 16_

17.4 **WHEN** augmenting oracle distribution, **THE System** **SHALL** support O' that adds θ_ν+1 ← O(θ_1) to existing oracles
   - _Requirements: Oracle augmentation from Definition 17_

17.5 **WHEN** lifting security properties, **THE System** **SHALL** apply Theorem 8 to preserve ROM properties in AROM
   - _Requirements: Security lifting_

17.6 **WHEN** lifting signatures, **THE System** **SHALL** ensure EU-CMA in ROM implies EU-CMA in AROM
   - _Requirements: Signature lifting from Theorem 9_

17.7 **WHEN** lifting O-SNARKs, **THE System** **SHALL** ensure O-AdPoK in ROM implies O-AdPoK in AROM
   - _Requirements: O-SNARK lifting from Theorem 10_


### Requirement 18: Concrete Instantiations

**User Story:** As a system builder, I want concrete instantiations of the framework, so that I can deploy real systems.

#### Acceptance Criteria

18.1 **WHERE** Groth16 is used, **THE System** **SHALL** modify prover to query (A, B, C) to ROM and output (A, B, C, r)
   - _Requirements: Groth16 instantiation from Section 2.1_

18.2 **WHERE** Groth16 verifier is used, **THE System** **SHALL** check Groth16 verification and oracle response correctness
   - _Requirements: Modified Groth16 verifier_

18.3 **WHERE** Marlin is used, **THE System** **SHALL** support PIOP+KZG compilation with SLE in AGM+ROM
   - _Requirements: Marlin instantiation_

18.4 **WHERE** Plonk is used, **THE System** **SHALL** support PIOP+KZG compilation with SLE in AGM+ROM
   - _Requirements: Plonk instantiation_

18.5 **WHERE** Sonic is used, **THE System** **SHALL** support PIOP+KZG compilation with SLE in AGM+ROM
   - _Requirements: Sonic instantiation_

18.6 **WHERE** BLS signatures are used, **THE System** **SHALL** support KZG extraction in presence of BLS signing oracle
   - _Requirements: BLS+KZG from Appendix D_

18.7 **WHERE** Schnorr signatures are used, **THE System** **SHALL** support KZG extraction in presence of Schnorr signing oracle
   - _Requirements: Schnorr+KZG from Appendix D_

### Requirement 19: AHP to O-SNARK Compilation

**User Story:** As a compiler developer, I want to compile AHPs to O-SNARKs, so that I can build aggregate signatures from standard SNARKs.

#### Acceptance Criteria

19.1 **WHEN** compiling AHP, **THE System** **SHALL** use PCS with extraction in presence of signing oracle
   - _Requirements: Compilation from Theorem 7_

19.2 **WHEN** AHP prover runs, **THE System** **SHALL** commit to polynomials p_i using PCS and send commitments c_i
   - _Requirements: Interactive argument construction_

19.3 **WHEN** AHP verifier runs, **THE System** **SHALL** send challenges ρ_i generated by AHP verifier
   - _Requirements: Challenge generation_

19.4 **WHEN** AHP completes, **THE System** **SHALL** output evaluations y_i with proofs π_i for p_i(z_i) = y_i
   - _Requirements: Evaluation proofs_

19.5 **WHEN** applying Fiat-Shamir, **THE System** **SHALL** make protocol non-interactive using random oracle
   - _Requirements: Non-interactive transformation_

19.6 **WHEN** extracting from O-SNARK, **THE System** **SHALL** use PCS extractor to obtain polynomials from commitments
   - _Requirements: Polynomial extraction_

19.7 **WHERE** KZG is used with BLS, **THE System** **SHALL** verify extraction works with BLS signing oracle queries
   - _Requirements: KZG+BLS security_

19.8 **WHERE** KZG is used with Schnorr, **THE System** **SHALL** verify extraction works with Schnorr signing oracle queries
   - _Requirements: KZG+Schnorr security_


### Requirement 20: KZG Commitment Security Analysis

**User Story:** As a cryptographer, I want rigorous security analysis of KZG in presence of signing oracles, so that O-SNARKs are provably secure.

#### Acceptance Criteria

20.1 **WHEN** using KZG with BLS, **THE System** **SHALL** handle adversary with access to H: M → G_1 and signing oracle
   - _Requirements: KZG+BLS from Appendix D_

20.2 **WHEN** adversary outputs KZG commitment, **THE System** **SHALL** require group representation in terms of (crs, Q_σ)
   - _Requirements: Algebraic KZG adversary_

20.3 **WHEN** analyzing BLS signatures, **THE System** **SHALL** use Q_σ containing (g_i, σ_i) where σ_i = g_i^sk
   - _Requirements: BLS signature structure_

20.4 **WHEN** non-zero δ appears, **THE System** **SHALL** reduce to discrete log problem
   - _Requirements: Discrete log reduction_

20.5 **WHEN** using KZG with Schnorr, **THE System** **SHALL** handle adversary with access to H: G × M → Z_p and signing oracle
   - _Requirements: KZG+Schnorr_

20.6 **WHEN** analyzing Schnorr signatures, **THE System** **SHALL** use Q_σ containing (R_i, z_i) satisfying R_i · vk^e_i · g^(-z_i) = 1
   - _Requirements: Schnorr signature structure_

20.7 **WHEN** adversary outputs with R_i dependencies, **THE System** **SHALL** substitute R_i with equivalent representation in (g, vk)
   - _Requirements: Representation substitution_

20.8 **WHEN** reducing to discrete log, **THE System** **SHALL** construct adversary B that breaks discrete log if KZG extraction fails
   - _Requirements: Security reduction_

### Requirement 21: Auxiliary Input and Oracle Families

**User Story:** As a protocol designer, I want proper auxiliary input handling, so that O-SNARKs work with signature schemes.

#### Acceptance Criteria

21.1 **WHEN** defining Z_Σ, **THE System** **SHALL** sample pp_Σ, generate (vk, sk), and output (aux := vk, st := sk)
   - _Requirements: Auxiliary input from Fig. 6_

21.2 **WHEN** defining O_sk, **THE System** **SHALL** implement signing oracle that computes σ ← sign^θ(sk, m)
   - _Requirements: Signing oracle_

21.3 **WHEN** Z-auxiliary input is used, **THE System** **SHALL** sample aux ← Z(1^λ) and provide to adversary
   - _Requirements: Z-auxiliary input SNARKs_

21.4 **WHEN** extractor runs with auxiliary input, **THE System** **SHALL** ensure E succeeds given (pp, i, aux, x, π, Q, tr_A, Γ)
   - _Requirements: Extraction with auxiliary input_


### Requirement 22: Circuit Satisfiability with Oracle Access

**User Story:** As a circuit designer, I want circuits that can make oracle queries, so that I can represent relativized computations.

#### Acceptance Criteria

22.1 **WHEN** defining R_csat, **THE System** **SHALL** represent {(C, x, w) : C(x, w) = 1}
   - _Requirements: Standard circuit satisfiability_

22.2 **WHEN** defining R^θ_csat, **THE System** **SHALL** represent {(C, x, w) : C^θ(x, w) = 1}
   - _Requirements: Oracle circuit satisfiability_

22.3 **WHEN** circuit makes oracle query, **THE System** **SHALL** include transcript tr := (q, r) in witness
   - _Requirements: Oracle transcript in witness_

22.4 **WHEN** checking oracle satisfiability, **THE System** **SHALL** verify ∃tr: C'(x, w, tr) = 1 ∧ θ(q) = r
   - _Requirements: Oracle consistency check_

22.5 **WHEN** circuits use group operations, **THE System** **SHALL** support wires labeled by group elements and gates for group operations
   - _Requirements: Group-aware circuits_

22.6 **WHEN** representing verifier in circuit, **THE System** **SHALL** encode V^θ algorithm including oracle queries
   - _Requirements: Verifier circuit representation_

### Requirement 23: Indexed Oracle Relations

**User Story:** As a relation designer, I want indexed oracle relations, so that I can parameterize computations by circuits and oracles.

#### Acceptance Criteria

23.1 **WHEN** defining indexed relation, **THE System** **SHALL** represent tuples (i, x, w) where i is circuit index
   - _Requirements: Indexed relations_

23.2 **WHEN** defining oracle indexed relation, **THE System** **SHALL** represent R^O as set {R^θ : θ ∈ supp(O)}
   - _Requirements: Oracle parameterization_

23.3 **WHEN** checking membership, **THE System** **SHALL** verify (i, x, w) ∈ R^θ iff circuit i outputs 1 on (x, w) with oracle θ
   - _Requirements: Membership criterion_

23.4 **WHEN** defining language, **THE System** **SHALL** compute L(R) = {(i, x, y) : ∃w, (i, x, y, w) ∈ R}
   - _Requirements: Language induced by relation_

### Requirement 24: Negligible Functions and Security Parameters

**User Story:** As a security analyst, I want proper negligible function handling, so that security bounds are rigorous.

#### Acceptance Criteria

24.1 **WHEN** defining negligible function, **THE System** **SHALL** ensure f: N → R_≥0 satisfies ∀e ∈ R_>0, ∃λ_0: f(λ) < 1/λ^e for λ ≥ λ_0
   - _Requirements: Negligible function definition_

24.2 **WHEN** security parameter λ is used, **THE System** **SHALL** ensure all algorithms are polynomial in λ
   - _Requirements: Polynomial-time algorithms_

24.3 **WHEN** checking security bounds, **THE System** **SHALL** verify advantage is ≤ negl(λ)
   - _Requirements: Negligible advantage_

24.4 **WHEN** composing security reductions, **THE System** **SHALL** ensure composed advantage remains negligible
   - _Requirements: Composition of negligible functions_


### Requirement 25: Efficiency and Optimization

**User Story:** As a performance engineer, I want optimizations that reduce overhead, so that the system is practical.

#### Acceptance Criteria

25.1 **WHEN** Fiat-Shamir is used, **THE System** **SHALL** achieve g = ∅ since verifier queries entire (statement, proof)
   - _Requirements: Zero overhead for Fiat-Shamir from efficiency note_

25.2 **WHEN** verifier already queries group elements, **THE System** **SHALL** only force remaining queries not in tr_V
   - _Requirements: Minimal oracle forcing_

25.3 **WHEN** extractor uses group representations, **THE System** **SHALL** use single Γ for all iterations avoiding exponential blowup
   - _Requirements: Efficient extraction_

25.4 **WHEN** parsing group representations, **THE System** **SHALL** use efficient parsing without recomputation
   - _Requirements: Efficient representation parsing_

25.5 **WHERE** parallel extraction is possible, **THE System** **SHALL** support parallel invocation of E for PCD
   - _Requirements: Parallelizable PCD extraction_

### Requirement 26: Correctness Proofs

**User Story:** As a verification engineer, I want complete correctness proofs, so that I can trust the implementation.

#### Acceptance Criteria

26.1 **WHEN** proving IVC correctness, **THE System** **SHALL** verify base case: dpt^≤0_F(z_0) = ⊤ ⇒ V^θ accepts (z_0, z_0, ⊥)
   - _Requirements: Base case correctness from Theorem 3_

26.2 **WHEN** proving IVC correctness, **THE System** **SHALL** verify inductive case: F(z_(i-1), w_i) = z_i ∧ V^θ accepts (z_0, z_(i-1), π_(i-1)) ⇒ V^θ accepts (z_0, z_i, π_i)
   - _Requirements: Inductive correctness_

26.3 **WHEN** proving aggregate signature correctness, **THE System** **SHALL** verify honest signatures lead to accepting aggregate
   - _Requirements: Aggregate correctness from Theorem 4_

26.4 **WHEN** proving completeness, **THE System** **SHALL** ensure Pr[(i,x,w) ∈ R^θ ⇒ V^θ accepts] = 1
   - _Requirements: Completeness property_

### Requirement 27: Knowledge Soundness Proofs

**User Story:** As a security researcher, I want rigorous knowledge soundness proofs, so that extraction is guaranteed.

#### Acceptance Criteria

27.1 **WHEN** proving IVC knowledge soundness, **THE System** **SHALL** construct extractor Ext that outputs (w_i, z_i)_i∈[d]
   - _Requirements: IVC extractor from Theorem 3_

27.2 **WHEN** proving extraction correctness, **THE System** **SHALL** verify ∀i ∈ [d]: F(z_(i-1), w_i) = z_i
   - _Requirements: Witness validity_

27.3 **WHEN** proving extraction completeness, **THE System** **SHALL** verify z_d = z_out
   - _Requirements: Output consistency_

27.4 **WHEN** extraction fails, **THE System** **SHALL** construct algebraic adversary against rel-SNARK
   - _Requirements: Reduction to SNARK security_

27.5 **WHEN** proving aggregate signature soundness, **THE System** **SHALL** extract individual signatures (σ_1, ..., σ_n)
   - _Requirements: Signature extraction from Theorem 5_

27.6 **WHEN** aggregate extraction fails, **THE System** **SHALL** construct adversary against either EU-CMA or O-AdPoK
   - _Requirements: Security reduction_


### Requirement 28: Succinctness Properties

**User Story:** As a system architect, I want succinctness guarantees, so that verification is efficient.

#### Acceptance Criteria

28.1 **WHEN** verifying rel-SNARK, **THE System** **SHALL** ensure runtime is poly(λ + |x|) independent of |i|
   - _Requirements: SNARK succinctness_

28.2 **WHEN** verifying IVC, **THE System** **SHALL** ensure runtime is poly(λ + |x|) independent of |F| and depth
   - _Requirements: IVC succinctness_

28.3 **WHEN** verifying aggregate signature, **THE System** **SHALL** ensure runtime is poly(λ + n) where n is number of signatures
   - _Requirements: Aggregate succinctness_

28.4 **WHEN** proof size is measured, **THE System** **SHALL** ensure |π| is poly(λ) independent of witness size
   - _Requirements: Proof succinctness_

### Requirement 29: Instantiation from Existing SNARKs

**User Story:** As a SNARK user, I want to use existing SNARKs in the framework, so that I can leverage proven implementations.

#### Acceptance Criteria

29.1 **WHERE** Groth16 is instantiated, **THE System** **SHALL** modify to query (A, B, C) to ROM
   - _Requirements: Groth16 modification_

29.2 **WHERE** Groth16 is instantiated, **THE System** **SHALL** lift to AGM+AROM using [CCG+23] technique
   - _Requirements: Groth16 lifting_

29.3 **WHERE** Marlin is instantiated, **THE System** **SHALL** use PIOP+KZG with SLE in AGM+ROM
   - _Requirements: Marlin instantiation_

29.4 **WHERE** Plonk is instantiated, **THE System** **SHALL** use PIOP+KZG with SLE in AGM+ROM
   - _Requirements: Plonk instantiation_

29.5 **WHERE** Sonic is instantiated, **THE System** **SHALL** use PIOP+KZG with SLE in AGM+ROM
   - _Requirements: Sonic instantiation_

29.6 **WHERE** Lunar is instantiated, **THE System** **SHALL** use PIOP+KZG with SLE in AGM+ROM
   - _Requirements: Lunar instantiation_

### Requirement 30: Testing and Validation

**User Story:** As a QA engineer, I want comprehensive tests, so that the implementation is correct.

#### Acceptance Criteria

30.1 **WHEN** testing AGM adversary, **THE System** **SHALL** verify group representations are provided for all outputs
   - _Requirements: AGM compliance testing_

30.2 **WHEN** testing oracle transcript, **THE System** **SHALL** verify all queries and responses are recorded
   - _Requirements: Transcript completeness_

30.3 **WHEN** testing IVC base case, **THE System** **SHALL** verify acceptance for valid base inputs
   - _Requirements: Base case testing_

30.4 **WHEN** testing IVC inductive case, **THE System** **SHALL** verify acceptance for valid recursive proofs
   - _Requirements: Inductive case testing_

30.5 **WHEN** testing extraction, **THE System** **SHALL** verify extractor outputs valid witnesses
   - _Requirements: Extraction testing_

30.6 **WHEN** testing aggregate signatures, **THE System** **SHALL** verify aggregation and verification correctness
   - _Requirements: Aggregate signature testing_

30.7 **WHEN** testing security reductions, **THE System** **SHALL** verify adversary construction is correct
   - _Requirements: Reduction testing_


### Requirement 31: Error Handling and Edge Cases

**User Story:** As a robustness engineer, I want comprehensive error handling, so that the system fails gracefully.

#### Acceptance Criteria

31.1 **WHEN** group representation is missing, **THE System** **SHALL** reject algebraic adversary output
   - _Requirements: AGM enforcement_

31.2 **WHEN** oracle query is inconsistent, **THE System** **SHALL** detect and reject invalid transcript
   - _Requirements: Oracle consistency checking_

31.3 **WHEN** extraction fails, **THE System** **SHALL** properly construct security reduction adversary
   - _Requirements: Extraction failure handling_

31.4 **WHEN** depth bound is exceeded, **THE System** **SHALL** handle polynomial-bounded depth correctly
   - _Requirements: Depth bound handling_

31.5 **WHEN** base case is not reached, **THE System** **SHALL** detect infinite recursion attempts
   - _Requirements: Termination checking_

### Requirement 32: Documentation and Specifications

**User Story:** As a developer, I want complete documentation, so that I can understand and extend the system.

#### Acceptance Criteria

32.1 **WHEN** implementing AGM, **THE System** **SHALL** document group representation requirements
   - _Requirements: AGM documentation_

32.2 **WHEN** implementing rel-SNARK, **THE System** **SHALL** document oracle access patterns
   - _Requirements: Oracle documentation_

32.3 **WHEN** implementing IVC, **THE System** **SHALL** document recursive circuit structure
   - _Requirements: IVC documentation_

32.4 **WHEN** implementing aggregate signatures, **THE System** **SHALL** document signature aggregation protocol
   - _Requirements: Aggregate signature documentation_

32.5 **WHEN** implementing security proofs, **THE System** **SHALL** document all reduction steps
   - _Requirements: Security proof documentation_

### Requirement 33: Integration with Existing Systems

**User Story:** As a system integrator, I want compatibility with existing cryptographic libraries, so that I can reuse components.

#### Acceptance Criteria

33.1 **WHERE** pairing libraries are used, **THE System** **SHALL** integrate with standard pairing implementations
   - _Requirements: Pairing library integration_

33.2 **WHERE** elliptic curve libraries are used, **THE System** **SHALL** integrate with standard EC implementations
   - _Requirements: EC library integration_

33.3 **WHERE** hash functions are used, **THE System** **SHALL** support standard hash function interfaces
   - _Requirements: Hash function integration_

33.4 **WHERE** random oracles are used, **THE System** **SHALL** support pluggable oracle implementations
   - _Requirements: Oracle modularity_

33.5 **WHERE** existing SNARKs are used, **THE System** **SHALL** provide adapter interfaces
   - _Requirements: SNARK adapter pattern_


### Requirement 34: Performance Benchmarking

**User Story:** As a performance analyst, I want benchmarking capabilities, so that I can measure system performance.

#### Acceptance Criteria

34.1 **WHEN** benchmarking IVC prover, **THE System** **SHALL** measure time per recursive step
   - _Requirements: Prover performance measurement_

34.2 **WHEN** benchmarking IVC verifier, **THE System** **SHALL** measure verification time independent of depth
   - _Requirements: Verifier performance measurement_

34.3 **WHEN** benchmarking extractor, **THE System** **SHALL** measure extraction time scaling with depth
   - _Requirements: Extractor performance measurement_

34.4 **WHEN** benchmarking aggregate signatures, **THE System** **SHALL** measure aggregation and verification time
   - _Requirements: Aggregate performance measurement_

34.5 **WHEN** comparing with baselines, **THE System** **SHALL** measure overhead compared to non-AGM versions
   - _Requirements: Overhead measurement_

### Requirement 35: Cryptographic Parameter Selection

**User Story:** As a cryptographer, I want proper parameter selection, so that security levels are achieved.

#### Acceptance Criteria

35.1 **WHEN** selecting security parameter λ, **THE System** **SHALL** ensure 2^λ security against known attacks
   - _Requirements: Security parameter selection_

35.2 **WHEN** selecting group order p, **THE System** **SHALL** ensure p is prime with |p| ≥ 2λ bits
   - _Requirements: Group order selection_

35.3 **WHEN** selecting elliptic curves, **THE System** **SHALL** use curves with known security properties
   - _Requirements: Curve selection_

35.4 **WHEN** selecting hash functions, **THE System** **SHALL** use collision-resistant hash functions
   - _Requirements: Hash function selection_

35.5 **WHEN** selecting polynomial degrees, **THE System** **SHALL** ensure soundness error is ≤ d/|F|
   - _Requirements: Degree selection for AROM_

### Requirement 36: Formal Verification Support

**User Story:** As a formal methods engineer, I want verification-friendly code, so that I can prove correctness formally.

#### Acceptance Criteria

36.1 **WHEN** implementing algorithms, **THE System** **SHALL** use clear preconditions and postconditions
   - _Requirements: Contract-based programming_

36.2 **WHEN** implementing extractors, **THE System** **SHALL** specify extraction guarantees formally
   - _Requirements: Extraction contracts_

36.3 **WHEN** implementing reductions, **THE System** **SHALL** specify advantage bounds formally
   - _Requirements: Security reduction contracts_

36.4 **WHEN** implementing oracle interactions, **THE System** **SHALL** specify transcript invariants
   - _Requirements: Oracle invariants_

36.5 **WHERE** formal verification tools are used, **THE System** **SHALL** provide machine-checkable proofs
   - _Requirements: Machine-checkable proofs_


### Requirement 37: Advanced Features and Extensions

**User Story:** As a researcher, I want support for advanced features, so that I can explore new applications.

#### Acceptance Criteria

37.1 **WHERE** universal aggregate signatures are needed, **THE System** **SHALL** support aggregation across different signature schemes
   - _Requirements: Universal aggregation from Section 5.2_

37.2 **WHERE** proof aggregation is needed, **THE System** **SHALL** support aggregating multiple SNARK proofs
   - _Requirements: Proof aggregation_

37.3 **WHERE** multi-key homomorphic signatures are needed, **THE System** **SHALL** support composition with SNARKs
   - _Requirements: Homomorphic signature support_

37.4 **WHERE** functional signatures are needed, **THE System** **SHALL** support AGM-secure functional signatures
   - _Requirements: Functional signature support_

37.5 **WHERE** functional commitments are needed, **THE System** **SHALL** support AGM-secure functional commitments
   - _Requirements: Functional commitment support_

### Requirement 38: Comparison with Related Work

**User Story:** As a researcher, I want to understand differences from related work, so that I can position the contribution.

#### Acceptance Criteria

38.1 **WHEN** comparing with [CGSY24], **THE System** **SHALL** document extension to AGM-secure SNARKs
   - _Requirements: Comparison with prior IVC work_

38.2 **WHEN** comparing with [LS24], **THE System** **SHALL** document differences in AGM model (no protocol-specific constraints)
   - _Requirements: Extended-AGM comparison_

38.3 **WHEN** comparing with [MMZ25], **THE System** **SHALL** document subsumption of osROM by framework
   - _Requirements: osROM comparison_

38.4 **WHEN** comparing with [AAB+24, FN16], **THE System** **SHALL** document extension to AGM-secure signatures
   - _Requirements: Aggregate signature comparison_

38.5 **WHEN** comparing with standard assumption IVCs, **THE System** **SHALL** document efficiency trade-offs
   - _Requirements: Standard assumption comparison_

### Requirement 39: Future Work and Open Problems

**User Story:** As a researcher, I want to identify open problems, so that I can extend the work.

#### Acceptance Criteria

39.1 **WHERE** transparent setup SNARKs are desired, **THE System** **SHALL** document path to SLE analysis for Spartan/Hyrax
   - _Requirements: Transparent setup future work_

39.2 **WHERE** generic O-SNARK framework is desired, **THE System** **SHALL** document AGMOS-based approach
   - _Requirements: Generic O-SNARK framework_

39.3 **WHERE** other oracle models are desired, **THE System** **SHALL** document extensibility to new oracle models
   - _Requirements: Oracle model extensibility_

39.4 **WHERE** other cryptographic primitives are desired, **THE System** **SHALL** document template for new compositions
   - _Requirements: Composition template_


### Requirement 40: Implementation Architecture

**User Story:** As a software architect, I want a modular architecture, so that components can be developed and tested independently.

#### Acceptance Criteria

40.1 **WHEN** designing module structure, **THE System** **SHALL** separate AGM layer, oracle layer, SNARK layer, and IVC layer
   - _Requirements: Layered architecture_

40.2 **WHEN** implementing AGM module, **THE System** **SHALL** provide interfaces for algebraic adversaries and group representations
   - _Requirements: AGM module interface_

40.3 **WHEN** implementing oracle module, **THE System** **SHALL** provide interfaces for ROM, AROM, Signed ROM, and custom oracles
   - _Requirements: Oracle module interface_

40.4 **WHEN** implementing SNARK module, **THE System** **SHALL** provide interfaces for rel-SNARK and O-SNARK
   - _Requirements: SNARK module interface_

40.5 **WHEN** implementing IVC module, **THE System** **SHALL** provide interfaces for prover, verifier, and extractor
   - _Requirements: IVC module interface_

40.6 **WHEN** implementing aggregate signature module, **THE System** **SHALL** provide interfaces for aggregation and verification
   - _Requirements: Aggregate signature module interface_

40.7 **WHERE** dependency injection is used, **THE System** **SHALL** allow pluggable implementations of each layer
   - _Requirements: Dependency injection_

---

## Summary

This requirements document provides comprehensive coverage of the AGM-Secure Functionalities framework, including:

- **Core AGM Infrastructure** (Req 1-4): Extended algebraic group model with oracle support and group element parsing
- **Incremental Computation** (Req 5): Function samplers and depth tracking for IVC
- **IVC Implementation** (Req 6-11): Complete IVC algorithms, recursive circuits, prover/verifier, extractor, and security reductions
- **PCD Extension** (Req 12): Directed acyclic graph computations
- **Aggregate Signatures** (Req 13-16): Construction and security proofs
- **O-SNARKs** (Req 14, 17-21): Extraction in presence of oracles, AROM lifting, and concrete instantiations
- **Circuit and Relation Infrastructure** (Req 22-24): Oracle-aware circuits and indexed relations
- **Optimization and Efficiency** (Req 25): Practical optimizations
- **Correctness and Security** (Req 26-27): Rigorous proofs
- **Succinctness** (Req 28): Verification efficiency guarantees
- **Instantiations** (Req 29): Support for Groth16, Marlin, Plonk, Sonic, etc.
- **Testing and Validation** (Req 30-31): Comprehensive testing and error handling
- **Documentation and Integration** (Req 32-33): Complete documentation and library integration
- **Performance and Parameters** (Req 34-35): Benchmarking and cryptographic parameter selection
- **Formal Verification** (Req 36): Support for formal methods
- **Advanced Features** (Req 37-39): Extensions and future work
- **Architecture** (Req 40): Modular implementation design

All requirements follow the EARS (Easy Approach to Requirements Syntax) pattern and INCOSE semantic quality rules, ensuring they are:
- Unambiguous and testable
- Free from escape clauses and vague terms
- Solution-free (focusing on what, not how)
- Traceable to the paper's technical content

Each requirement includes specific acceptance criteria with references to the relevant sections of the paper, ensuring complete coverage of all technical details.

