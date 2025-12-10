# Design Document: AGM-Secure Functionalities with Cryptographic Proofs

## Overview

This design document provides a complete, in-depth technical specification for implementing the AGM-Secure Functionalities framework. The system enables provably secure composition of AGM-secure cryptographic primitives with SNARKs, achieving unbounded-depth IVC and aggregate signatures.

### Core Innovation

The paper solves a fundamental problem: when composing AGM-secure primitives (where security relies on algebraic adversaries providing group representations), standard extraction techniques fail because extractors cannot maintain algebraic properties through composition. The solution introduces a modified AGM model and oracle-forcing technique that preserves group representations through recursive extraction.

### Mathematical Foundation

The framework is built on three key mathematical insights:

1. **Extended AGM**: Adversaries must provide group representations not only for explicit outputs but also for group elements in oracle transcripts
2. **Oracle Forcing**: Provers must query all group elements to oracle θ, ensuring representations are available in transcript
3. **Straight-Line Extraction**: Single group representation Γ suffices for all extraction iterations, avoiding exponential blowup

---

## Architecture

### System Layers

```
┌─────────────────────────────────────────────────────────┐
│                  Application Layer                       │
│  (IVC, PCD, Aggregate Signatures, Proof Aggregation)   │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              Composition Framework Layer                 │
│   (Oracle Forcing, Extraction Composition, Reductions)  │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              Relativized SNARK Layer                     │
│        (rel-SNARK, O-SNARK, Circuit Compilation)        │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│                 Oracle Model Layer                       │
│         (ROM, AROM, Signed ROM, Oracle Emulation)       │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              Algebraic Group Model Layer                 │
│    (Group Representations, Algebraic Adversaries)       │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              Cryptographic Primitives Layer              │
│  (Groups, Pairings, Hash Functions, Signature Schemes)  │
└─────────────────────────────────────────────────────────┘
```



## Components and Interfaces

### 1. Algebraic Group Model (AGM) Component

#### 1.1 Group Representation Manager

**Purpose**: Track and validate group representations for all group elements

**Mathematical Foundation**:
- For group element y output by adversary A^alg, require representation Γ such that y = Γ^T x
- For group elements y^θ in oracle transcript, require representation such that y||y^θ = Γ^T x
- Representation matrix Γ ∈ F^(|y|+|y^θ|)×|x| where F is the field

**Data Structures**:
```rust
/// Group representation tracking
struct GroupRepresentation<F: Field, G: Group> {
    /// Group elements that form the basis
    basis: Vec<G>,
    
    /// Coefficient matrix Γ where output = Γ^T · basis
    coefficients: Vec<Vec<F>>,
    
    /// Mapping from group element to its representation
    representation_map: HashMap<G, Vec<F>>,
}

/// Algebraic adversary output
struct AlgebraicOutput<F: Field, G: Group> {
    /// Explicit output group elements
    output_elements: Vec<G>,
    
    /// Group elements queried to oracle
    oracle_queried_elements: Vec<G>,
    
    /// Group representations for output || oracle_queried
    representations: GroupRepresentation<F, G>,
}
```

**Key Operations**:
- `add_basis_element(g: G)`: Add group element to basis
- `provide_representation(y: G, coeffs: Vec<F>)`: Provide representation for output element
- `verify_representation(y: G, coeffs: Vec<F>) -> bool`: Verify y = Γ^T x
- `extract_from_transcript(tr: OracleTranscript) -> Vec<G>`: Extract group elements from transcript
- `get_representation(y: G) -> Option<Vec<F>>`: Retrieve stored representation

**Invariants**:
- All output group elements must have valid representations
- All oracle-queried group elements must have valid representations
- Representations must be linear combinations of basis elements only

#### 1.2 Algebraic Adversary Interface

**Purpose**: Define interface for algebraic adversaries that provide group representations

**Interface**:
```rust
trait AlgebraicAdversary<F: Field, G: Group, O: Oracle> {
    /// Run adversary with oracle access
    fn run(&mut self, pp: &PublicParameters<G>, oracle: &mut O) 
        -> AlgebraicOutput<F, G>;
    
    /// Verify adversary is algebraic (provides all representations)
    fn verify_algebraic(&self, output: &AlgebraicOutput<F, G>) -> bool;
}
```

**Properties**:
- Must provide representations for all group elements in output
- Must provide representations for all group elements in oracle transcript
- Representations must be computable in polynomial time


### 2. Oracle Model Component

#### 2.1 Oracle Distribution Framework

**Purpose**: Manage different oracle types (ROM, AROM, Signed ROM) and their distributions

**Mathematical Foundation**:
- Oracle distribution O_λ samples oracle θ: X → Y
- Oracle transcript tr_A = {(q_i, r_i)} records all queries and responses
- Consistency: θ(q) must return same r for repeated queries

**Data Structures**:
```rust
/// Oracle transcript entry
struct OracleQuery<X, Y> {
    query: X,
    response: Y,
}

/// Oracle transcript
struct OracleTranscript<X, Y> {
    queries: Vec<OracleQuery<X, Y>>,
    query_map: HashMap<X, Y>,  // For consistency checking
}

/// Oracle trait
trait Oracle<X, Y> {
    /// Query oracle with input
    fn query(&mut self, input: X) -> Y;
    
    /// Get full transcript
    fn transcript(&self) -> &OracleTranscript<X, Y>;
    
    /// Check consistency
    fn is_consistent(&self) -> bool;
}
```

**Key Operations**:
- `query(x: X) -> Y`: Query oracle and record in transcript
- `get_transcript() -> OracleTranscript`: Retrieve full transcript
- `verify_consistency() -> bool`: Check all queries are consistent
- `extract_group_elements() -> Vec<G>`: Extract group elements from transcript

#### 2.2 Random Oracle Model (ROM)

**Purpose**: Standard random oracle implementation

**Implementation**:
```rust
struct RandomOracle<X: Hash, Y> {
    transcript: OracleTranscript<X, Y>,
    rng: ChaCha20Rng,
}

impl<X: Hash, Y: Uniform> Oracle<X, Y> for RandomOracle<X, Y> {
    fn query(&mut self, input: X) -> Y {
        if let Some(cached) = self.transcript.query_map.get(&input) {
            return cached.clone();
        }
        
        let response = self.sample_uniform(&input);
        self.transcript.queries.push(OracleQuery { query: input.clone(), response: response.clone() });
        self.transcript.query_map.insert(input, response.clone());
        response
    }
}
```

#### 2.3 Arithmetized Random Oracle Model (AROM)

**Purpose**: Oracle model supporting succinct proofs about oracle queries

**Mathematical Foundation**:
- AROM = (ro, wo, vco) where:
  - ro: random oracle
  - wo: witness oracle computing wo(x) := B^ro(x, μ_x)
  - vco: verification oracle (low-degree extension of verification function)

**Data Structures**:
```rust
struct AROM<F: Field> {
    /// Random oracle component
    ro: RandomOracle<Vec<F>, F>,
    
    /// Witness oracle (computes B^ro(x, μ_x))
    wo: WitnessOracle<F>,
    
    /// Verification oracle (low-degree extension)
    vco: VerificationOracle<F>,
    
    /// Degree bound for vco
    degree_bound: usize,
}

impl AROM<F> {
    /// Query random oracle
    fn query_ro(&mut self, x: Vec<F>) -> F {
        self.ro.query(x)
    }
    
    /// Query witness oracle
    fn query_wo(&mut self, x: Vec<F>) -> Vec<F> {
        self.wo.compute(x, &mut self.ro)
    }
    
    /// Query verification oracle
    fn query_vco(&mut self, x: Vec<F>) -> F {
        self.vco.evaluate(x)
    }
}
```

**Properties**:
- vco is low-degree extension (degree ≤ d)
- wo computes witness using ro
- All three oracles maintain consistent transcripts

#### 2.4 Signed Random Oracle Model

**Purpose**: Oracle model with signing oracle access for aggregate signatures

**Data Structures**:
```rust
struct SignedOracle<M, Sig> {
    /// Random oracle
    ro: RandomOracle<Vec<u8>, Vec<u8>>,
    
    /// Signing oracle
    signing_oracle: SigningOracle<M, Sig>,
    
    /// Secret key (for signing oracle)
    sk: SecretKey,
}

struct SigningOracle<M, Sig> {
    /// Transcript of signing queries
    signing_transcript: Vec<(M, Sig)>,
    
    /// Secret key
    sk: SecretKey,
}

impl<M, Sig> SigningOracle<M, Sig> {
    fn sign(&mut self, message: M) -> Sig {
        let signature = self.sign_internal(&self.sk, &message);
        self.signing_transcript.push((message, signature.clone()));
        signature
    }
    
    fn get_signing_queries(&self) -> &Vec<(M, Sig)> {
        &self.signing_transcript
    }
}
```

### 3. Relativized SNARK Component

#### 3.1 rel-SNARK Interface

**Purpose**: SNARK with oracle access and AGM-aware extraction

**Mathematical Foundation**:
- Setup: G(1^λ) → pp
- Indexing: I^θ(i, pp) → (ipk, ivk)
- Proving: P^θ(ipk, x, w) → π
- Verification: V^θ(ivk, x, π) → ⊤/⊥
- Extraction: E(pp, i, x, π, tr_P, Γ) → w

**Interface**:
```rust
trait RelativizedSNARK<F: Field, G: Group, O: Oracle> {
    type PublicParameters;
    type IndexerKey;
    type VerifierKey;
    type Proof;
    type Circuit;
    type Statement;
    type Witness;
    
    /// Setup algorithm
    fn setup(lambda: usize) -> Self::PublicParameters;
    
    /// Indexing algorithm with oracle access
    fn index(
        circuit: &Self::Circuit,
        pp: &Self::PublicParameters,
        oracle: &mut O
    ) -> (Self::IndexerKey, Self::VerifierKey);
    
    /// Prover algorithm with oracle access
    fn prove(
        ipk: &Self::IndexerKey,
        statement: &Self::Statement,
        witness: &Self::Witness,
        oracle: &mut O
    ) -> Self::Proof;
    
    /// Verifier algorithm with oracle access
    fn verify(
        ivk: &Self::VerifierKey,
        statement: &Self::Statement,
        proof: &Self::Proof,
        oracle: &mut O
    ) -> bool;
    
    /// Extractor algorithm (AGM-aware)
    fn extract(
        pp: &Self::PublicParameters,
        circuit: &Self::Circuit,
        statement: &Self::Statement,
        proof: &Self::Proof,
        prover_transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
        group_representations: &GroupRepresentation<F, G>
    ) -> Result<Self::Witness, ExtractionError>;
}
```

**Properties**:
- Completeness: Honest proofs always verify
- Knowledge soundness: Extractor succeeds with overwhelming probability
- Succinctness: Verification time poly(λ + |x|), independent of |i|
- SLE in AGM+O: Straight-line extraction in extended AGM with oracle

#### 3.2 Group Element Parsing

**Purpose**: Extract group elements from mixed data structures for oracle forcing

**Mathematical Foundation**:
- For lst ∈ G^ℓ_G × F^ℓ_F, group(lst) extracts ℓ_G group elements
- Ordering must be publicly known and deterministic
- Used to identify which elements need oracle queries

**Implementation**:
```rust
struct GroupParser<G: Group, F: Field> {
    /// Known group element positions in data structure
    group_positions: Vec<usize>,
}

impl<G: Group, F: Field> GroupParser<G, F> {
    /// Parse mixed list to extract group elements
    fn parse(&self, data: &[u8]) -> Vec<G> {
        let mut group_elements = Vec::new();
        
        for &pos in &self.group_positions {
            let element = self.deserialize_group_element(&data[pos..]);
            group_elements.push(element);
        }
        
        group_elements
    }
    
    /// Extract group elements from statement and proof
    fn extract_from_statement_proof(
        &self,
        statement: &[u8],
        proof: &[u8]
    ) -> Vec<G> {
        let mut elements = self.parse(statement);
        elements.extend(self.parse(proof));
        elements
    }
    
    /// Compute set difference: elements in (z, π) but not in tr_V
    fn compute_oracle_forcing_set(
        &self,
        statement_proof_elements: Vec<G>,
        verifier_transcript_elements: Vec<G>
    ) -> Vec<G> {
        statement_proof_elements
            .into_iter()
            .filter(|e| !verifier_transcript_elements.contains(e))
            .collect()
    }
}
```

**Key Insight**: For Fiat-Shamir transformed SNARKs, verifier queries entire (statement, proof) to ROM, so g = ∅ (zero overhead).

### 4. IVC Core Component

#### 4.1 Incremental Computation Definition

**Purpose**: Define incremental computations with depth tracking

**Mathematical Foundation**:
- Function sampler: F(1^λ) → F where F: {0,1}^n_in × {0,1}^n_w → {0,1}^n_out
- Incremental computation: (F, dpt^≤) where dpt^≤ is depth predicate family
- Well-founded: dpt^≤_D_F(z') = ⊤ ∧ z→^F_w z' ⇒ dpt^≤_(D-1)_F(z) = ⊤
- Base case: dpt^≤0_F(z) = ⊤ identifies source nodes

**Data Structures**:
```rust
struct IncrementalComputation<F: Field> {
    /// Function being computed incrementally
    function: Box<dyn Fn(&[F], &[F]) -> Vec<F>>,
    
    /// Depth predicate family
    depth_predicates: DepthPredicates<F>,
    
    /// Input/output sizes
    n_in: usize,
    n_w: usize,
    n_out: usize,
}

struct DepthPredicates<F: Field> {
    /// Check if state has depth ≤ D
    predicates: HashMap<usize, Box<dyn Fn(&[F]) -> bool>>,
}

impl<F: Field> IncrementalComputation<F> {
    /// Apply function: z_i = F(z_{i-1}, w_i)
    fn apply(&self, z_prev: &[F], w: &[F]) -> Vec<F> {
        (self.function)(z_prev, w)
    }
    
    /// Check if state is at depth ≤ D
    fn check_depth(&self, state: &[F], depth: usize) -> bool {
        self.depth_predicates.predicates
            .get(&depth)
            .map(|pred| pred(state))
            .unwrap_or(false)
    }
    
    /// Check if state is base case (depth 0)
    fn is_base_case(&self, state: &[F]) -> bool {
        self.check_depth(state, 0)
    }
}
```

#### 4.2 IVC Algorithms

**Purpose**: Core IVC prover, verifier, and extractor

**IVC Prover with Oracle Forcing**:
```rust
struct IVCProver<F: Field, G: Group, O: Oracle, S: RelativizedSNARK<F, G, O>> {
    ipk: S::IndexerKey,
    pp: S::PublicParameters,
    group_parser: GroupParser<G, F>,
}

impl<F, G, O, S> IVCProver<F, G, O, S> 
where
    F: Field,
    G: Group,
    O: Oracle,
    S: RelativizedSNARK<F, G, O>
{
    /// Prove IVC step with AGM modifications
    fn prove_step(
        &self,
        z_0: &[F],           // Initial state
        z_i: &[F],           // Current state
        w_i: &[F],           // Current witness
        z_prev: &[F],        // Previous state
        pi_prev: &S::Proof,  // Previous proof
        oracle: &mut O
    ) -> S::Proof {
        // Step 1: Simulate verifier to get transcript
        let ivk = self.get_verifier_key();
        let statement_prev = self.build_statement(z_0, z_prev);
        
        // Run verifier to get tr_V
        let mut verifier_oracle = oracle.clone();
        let _ = S::verify(&ivk, &statement_prev, pi_prev, &mut verifier_oracle);
        let tr_v = verifier_oracle.transcript();
        
        // Step 2: Extract group elements from (z_prev, π_prev)
        let statement_proof_bytes = self.serialize_statement_proof(z_prev, pi_prev);
        let all_group_elements = self.group_parser.parse(&statement_proof_bytes);
        
        // Step 3: Extract group elements from tr_V
        let tr_v_group_elements = self.extract_group_elements_from_transcript(tr_v);
        
        // Step 4: Compute g = group(z_prev || π_prev) \ group(tr_V)
        let g = self.group_parser.compute_oracle_forcing_set(
            all_group_elements,
            tr_v_group_elements
        );
        
        // Step 5: Force oracle queries for g
        let r = self.force_oracle_queries(&g, oracle);
        
        // Step 6: Generate proof with oracle responses
        let statement = self.build_statement(z_0, z_i);
        let witness = self.build_witness(w_i, z_prev, pi_prev, &r);
        
        S::prove(&self.ipk, &statement, &witness, oracle)
    }
    
    /// Force oracle queries for group elements
    fn force_oracle_queries(&self, elements: &[G], oracle: &mut O) -> Vec<Vec<u8>> {
        elements.iter()
            .map(|g| {
                let query = self.serialize_group_element(g);
                oracle.query(query)
            })
            .collect()
    }
}
```

**IVC Verifier**:
```rust
struct IVCVerifier<F: Field, G: Group, O: Oracle, S: RelativizedSNARK<F, G, O>> {
    ivk: S::VerifierKey,
}

impl<F, G, O, S> IVCVerifier<F, G, O, S>
where
    F: Field,
    G: Group,
    O: Oracle,
    S: RelativizedSNARK<F, G, O>
{
    fn verify(
        &self,
        z_0: &[F],
        z_out: &[F],
        proof: &S::Proof,
        oracle: &mut O
    ) -> bool {
        // Base case: z_0 = z_out
        if z_0 == z_out {
            return true;
        }
        
        // Recursive case: verify SNARK proof
        let statement = self.build_statement(z_0, z_out);
        S::verify(&self.ivk, &statement, proof, oracle)
    }
}
```

#### 4.3 IVC Extractor (Straight-Line)

**Purpose**: Extract witness chain without exponential blowup

**Key Innovation**: Use single group representation Γ from initial adversary output for all iterations

**Implementation**:
```rust
struct IVCExtractor<F: Field, G: Group, O: Oracle, S: RelativizedSNARK<F, G, O>> {
    pp: S::PublicParameters,
    circuit: S::Circuit,
}

impl<F, G, O, S> IVCExtractor<F, G, O, S>
where
    F: Field,
    G: Group,
    O: Oracle,
    S: RelativizedSNARK<F, G, O>
{
    /// Extract witness chain using straight-line extraction
    fn extract(
        &self,
        z_0: &[F],
        z_out: &[F],
        proof_out: &S::Proof,
        prover_transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
        group_representations: &GroupRepresentation<F, G>
    ) -> Result<Vec<(Vec<F>, Vec<F>)>, ExtractionError> {
        let mut witness_chain = Vec::new();
        let mut current_statement = self.build_statement(z_0, z_out);
        let mut current_proof = proof_out.clone();
        let mut is_last = false;
        
        // Iterate until base case
        while !is_last {
            // Extract witness for current step using SNARK extractor
            let extracted = S::extract(
                &self.pp,
                &self.circuit,
                &current_statement,
                &current_proof,
                prover_transcript,
                group_representations  // Same Γ for all iterations!
            )?;
            
            // Parse extracted witness: (w_loc, z_in, π_in, r^in)
            let (w_loc, z_in, pi_in, r_in) = self.parse_extracted_witness(&extracted);
            
            // Get z_out from current statement
            let z_out_current = self.extract_z_out(&current_statement);
            
            // Add to witness chain
            witness_chain.push((w_loc.clone(), z_out_current.clone()));
            
            // Check if base case reached
            if self.is_base_case(&z_in) {
                is_last = true;
            } else {
                // Update for next iteration
                current_statement = self.build_statement(z_0, &z_in);
                current_proof = pi_in;
            }
        }
        
        Ok(witness_chain)
    }
    
    /// Parse extracted witness components
    fn parse_extracted_witness(
        &self,
        witness: &S::Witness
    ) -> (Vec<F>, Vec<F>, S::Proof, Vec<Vec<u8>>) {
        // Implementation depends on witness structure
        // Returns (w_loc, z_in, π_in, r^in)
        todo!()
    }
}
```

**Critical Property**: Using single Γ avoids exponential blowup because:
1. Initial adversary provides Γ for all group elements in (z_out, π_out)
2. For iteration i-1, circuit accepts ⇒ (z_in, π_in) group elements are in tr_P̃
3. Group elements in tr_P̃ have representations in Γ by parsing
4. No need to recursively compose representations

#### 4.4 Recursive Verification Circuit

**Purpose**: Circuit that checks function application and recursive verification

**Circuit Structure**:
```rust
struct RecursiveVerificationCircuit<F: Field, G: Group, O: Oracle, S: RelativizedSNARK<F, G, O>> {
    /// IVC verifier key
    ivk: S::VerifierKey,
    
    /// Function being computed
    function: Box<dyn Fn(&[F], &[F]) -> Vec<F>>,
    
    /// Depth predicates
    depth_predicates: DepthPredicates<F>,
}

impl<F, G, O, S> RecursiveVerificationCircuit<F, G, O, S>
where
    F: Field,
    G: Group,
    O: Oracle,
    S: RelativizedSNARK<F, G, O>
{
    /// Circuit computation: [CV_λ]^θ
    fn compute(
        &self,
        // Public inputs
        ivk: &S::VerifierKey,
        z_0: &[F],
        z_out: &[F],
        // Private inputs
        w_loc: &[F],
        z_in: &[F],
        pi_in: &S::Proof,
        r: &[Vec<u8>],
        oracle: &mut O
    ) -> bool {
        // Check 1: Function application
        let z_computed = (self.function)(z_in, w_loc);
        if z_computed != z_out {
            return false;
        }
        
        // Check 2: Base case or recursive case
        if self.depth_predicates.predicates[&0](z_in) {
            // Base case: z_in = z_0
            if z_in != z_0 {
                return false;
            }
        } else {
            // Recursive case: verify previous proof
            let statement = self.build_statement(ivk, z_0, z_in);
            if !S::verify(ivk, &statement, pi_in, oracle) {
                return false;
            }
        }
        
        // Check 3: Oracle forcing (AGM modification)
        // Compute g = group(z_in || π_in) \ group(tr_V)
        let g = self.compute_oracle_forcing_set(z_in, pi_in, oracle);
        
        // Verify oracle queries match r
        for (i, g_elem) in g.iter().enumerate() {
            let query = self.serialize_group_element(g_elem);
            let response = oracle.query(query);
            if response != r[i] {
                return false;
            }
        }
        
        true
    }
}
```

### 5. O-SNARK Component

#### 5.1 O-SNARK Definition

**Purpose**: SNARK with extraction in presence of additional oracles (e.g., signing oracles)

**Mathematical Foundation**:
- Extends rel-SNARK with O-AdPoK (adaptive proof of knowledge with oracle)
- Extractor E gets access to oracle transcript Q containing signing queries
- Security: Pr[V^θ accepts ∧ (x, w) ∉ R^θ] ≤ negl(λ) even with signing oracle access

**Interface**:
```rust
trait OSNARK<F: Field, G: Group, O: Oracle, AuxO: Oracle>: RelativizedSNARK<F, G, O> {
    type AuxiliaryInput;
    
    /// Extract with auxiliary oracle transcript
    fn extract_with_oracle(
        pp: &Self::PublicParameters,
        circuit: &Self::Circuit,
        aux: &Self::AuxiliaryInput,
        statement: &Self::Statement,
        proof: &Self::Proof,
        oracle_queries: &OracleTranscript<Vec<u8>, Vec<u8>>,  // Q: signing oracle queries
        prover_transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,  // tr_A
        group_representations: &GroupRepresentation<F, G>
    ) -> Result<Self::Witness, ExtractionError>;
}
```

#### 5.2 O-AdPoK Game

**Purpose**: Define adaptive proof of knowledge game with oracle access

**Game Structure**:
```rust
struct OAdPoKGame<F: Field, G: Group, O: Oracle, AuxO: Oracle, S: OSNARK<F, G, O, AuxO>> {
    pp: S::PublicParameters,
    oracle: O,
    aux_oracle: AuxO,
}

impl<F, G, O, AuxO, S> OAdPoKGame<F, G, O, AuxO, S>
where
    F: Field,
    G: Group,
    O: Oracle,
    AuxO: Oracle,
    S: OSNARK<F, G, O, AuxO>
{
    /// Run O-AdPoK game
    fn run<A: AlgebraicAdversary<F, G, O>>(
        &mut self,
        adversary: &mut A,
        aux_input_sampler: impl Fn(&O) -> (S::AuxiliaryInput, AuxO)
    ) -> bool {
        // Sample oracle
        let theta = self.oracle.sample();
        
        // Sample auxiliary input and auxiliary oracle
        let (aux, aux_oracle_state) = aux_input_sampler(&theta);
        self.aux_oracle = AuxO::from_state(aux_oracle_state);
        
        // Run adversary with both oracles
        let output = adversary.run_with_dual_oracle(
            &self.pp,
            &aux,
            &mut self.oracle,
            &mut self.aux_oracle
        );
        
        // Extract witness
        let extraction_result = S::extract_with_oracle(
            &self.pp,
            &output.circuit,
            &aux,
            &output.statement,
            &output.proof,
            self.aux_oracle.transcript(),
            self.oracle.transcript(),
            &output.representations
        );
        
        // Check if extraction fails but verification succeeds
        match extraction_result {
            Ok(witness) => {
                // Check if witness is invalid
                !self.verify_witness(&output.circuit, &output.statement, &witness)
            }
            Err(_) => {
                // Extraction failed, check if proof verifies
                S::verify(
                    &output.verifier_key,
                    &output.statement,
                    &output.proof,
                    &mut self.oracle
                )
            }
        }
    }
}
```

### 6. Aggregate Signature Component

#### 6.1 Aggregate Signature Construction

**Purpose**: Build aggregate signatures from AGM-secure signatures and O-SNARKs

**Mathematical Foundation**:
- Setup: Compute pp_Π (SNARK params), (ipk, ivk) (indexer/verifier keys), pp_Σ (signature params)
- Aggregation: Build SNARK proof that all individual signatures verify
- Verification: Verify single SNARK proof instead of n signatures

**Data Structures**:
```rust
struct AggregateSignature<F: Field, G: Group, O: Oracle, S: OSNARK<F, G, O, SigningOracle>> {
    /// SNARK public parameters
    pp_snark: S::PublicParameters,
    
    /// SNARK indexer and verifier keys
    ipk: S::IndexerKey,
    ivk: S::VerifierKey,
    
    /// Signature scheme parameters
    pp_sig: SignatureParameters<G>,
}

impl<F, G, O, S> AggregateSignature<F, G, O, S>
where
    F: Field,
    G: Group,
    O: Oracle,
    S: OSNARK<F, G, O, SigningOracle>
{
    /// Setup aggregate signature scheme
    fn setup(lambda: usize, oracle: &mut O) -> Self {
        // Setup SNARK
        let pp_snark = S::setup(lambda);
        
        // Build verification circuit
        let circuit = Self::build_verification_circuit();
        let (ipk, ivk) = S::index(&circuit, &pp_snark, oracle);
        
        // Setup signature scheme
        let pp_sig = SignatureScheme::setup(lambda);
        
        Self { pp_snark, ipk, ivk, pp_sig }
    }
    
    /// Aggregate signatures
    fn aggregate(
        &self,
        signatures: &[(VerificationKey<G>, Message, Signature<G>)],
        oracle: &mut O
    ) -> S::Proof {
        let n = signatures.len();
        
        // Build statement: (vk_i, m_i) for i ∈ [n]
        let statement = signatures.iter()
            .map(|(vk, m, _)| (vk.clone(), m.clone()))
            .collect::<Vec<_>>();
        
        // Compute verifier transcript for signature verifications
        let tr_sig = self.compute_signature_verifier_transcript(signatures, oracle);
        
        // Compute g = group(σ_i)_i∈[n] \ group(tr_Σ)
        let all_sig_elements = signatures.iter()
            .flat_map(|(_, _, sig)| self.extract_group_elements(sig))
            .collect::<Vec<_>>();
        
        let tr_sig_elements = self.extract_group_elements_from_transcript(&tr_sig);
        
        let g = all_sig_elements.into_iter()
            .filter(|e| !tr_sig_elements.contains(e))
            .collect::<Vec<_>>();
        
        // Force oracle queries
        let r = g.iter()
            .map(|elem| oracle.query(self.serialize_group_element(elem)))
            .collect::<Vec<_>>();
        
        // Build witness: ((σ_i)_i∈[n], r)
        let witness = self.build_aggregate_witness(signatures, &r);
        
        // Generate SNARK proof
        S::prove(&self.ipk, &statement, &witness, oracle)
    }
    
    /// Verify aggregate signature
    fn verify(
        &self,
        public_keys_messages: &[(VerificationKey<G>, Message)],
        aggregate_proof: &S::Proof,
        oracle: &mut O
    ) -> bool {
        let statement = public_keys_messages.to_vec();
        S::verify(&self.ivk, &statement, aggregate_proof, oracle)
    }
}
```

#### 6.2 Aggregate Verification Circuit

**Purpose**: Circuit that verifies all individual signatures

**Circuit Structure**:
```rust
struct AggregateVerificationCircuit<G: Group, O: Oracle> {
    /// Signature verification function
    verify_signature: Box<dyn Fn(&VerificationKey<G>, &Message, &Signature<G>, &mut O) -> bool>,
}

impl<G: Group, O: Oracle> AggregateVerificationCircuit<G, O> {
    /// Circuit computation
    fn compute(
        &self,
        // Public inputs: (vk_i, m_i) for i ∈ [n]
        public_keys_messages: &[(VerificationKey<G>, Message)],
        // Private inputs: (σ_i) for i ∈ [n], and r (oracle responses)
        signatures: &[Signature<G>],
        oracle_responses: &[Vec<u8>],
        oracle: &mut O
    ) -> bool {
        let n = public_keys_messages.len();
        
        if signatures.len() != n {
            return false;
        }
        
        // Check 1: All signatures verify
        for i in 0..n {
            let (vk, m) = &public_keys_messages[i];
            let sig = &signatures[i];
            
            if !(self.verify_signature)(vk, m, sig, oracle) {
                return false;
            }
        }
        
        // Check 2: Oracle forcing
        // Compute g = group(σ_i)_i∈[n] \ group(tr_Σ)
        let g = self.compute_oracle_forcing_set(signatures, oracle);
        
        // Verify oracle queries match r
        for (i, g_elem) in g.iter().enumerate() {
            let query = self.serialize_group_element(g_elem);
            let response = oracle.query(query);
            if response != oracle_responses[i] {
                return false;
            }
        }
        
        true
    }
}
```

### 7. PCD Extension Component

#### 7.1 PCD Data Structures

**Purpose**: Support proof-carrying data for DAG computations

**Mathematical Foundation**:
- PCD transcript: Directed acyclic graph with vertices labeled by w_loc and edges by messages
- Output: Message z_e where e is lexicographically-first edge to sink
- Compliance: ϕ^θ(z_e, w_loc, z) = 1 for each vertex

**Data Structures**:
```rust
struct PCDTranscript<F: Field> {
    /// DAG structure
    graph: DirectedAcyclicGraph<PCDVertex<F>, PCDEdge<F>>,
    
    /// Sink vertices (no outgoing edges)
    sinks: Vec<VertexId>,
}

struct PCDVertex<F: Field> {
    /// Local witness
    w_loc: Vec<F>,
    
    /// Incoming messages
    incoming_messages: Vec<Vec<F>>,
}

struct PCDEdge<F: Field> {
    /// Message on this edge
    message: Vec<F>,
    
    /// Source and target vertices
    source: VertexId,
    target: VertexId,
}

struct PCDProof<F: Field, P> {
    /// Proof for the output message
    proof: P,
    
    /// Output message
    output_message: Vec<F>,
}
```

#### 7.2 PCD Extractor

**Purpose**: Extract witnesses using breadth-first traversal

**Key Difference from IVC**: Store multiple (z, π) tuples per level for parallel extraction

**Implementation**:
```rust
struct PCDExtractor<F: Field, G: Group, O: Oracle, S: RelativizedSNARK<F, G, O>> {
    pp: S::PublicParameters,
    circuit: S::Circuit,
}

impl<F, G, O, S> PCDExtractor<F, G, O, S>
where
    F: Field,
    G: Group,
    O: Oracle,
    S: RelativizedSNARK<F, G, O>
{
    /// Extract PCD witnesses using breadth-first extraction
    fn extract(
        &self,
        output_message: &[F],
        proof: &S::Proof,
        prover_transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
        group_representations: &GroupRepresentation<F, G>
    ) -> Result<PCDTranscript<F>, ExtractionError> {
        let mut current_level = vec![(output_message.to_vec(), proof.clone())];
        let mut extracted_vertices = Vec::new();
        
        while !current_level.is_empty() {
            let mut next_level = Vec::new();
            
            // Process all tuples in current level
            for (message, prf) in current_level {
                // Extract witness for this message
                let statement = self.build_pcd_statement(&message);
                let extracted = S::extract(
                    &self.pp,
                    &self.circuit,
                    &statement,
                    &prf,
                    prover_transcript,
                    group_representations
                )?;
                
                // Parse extracted witness
                let (w_loc, incoming_messages, incoming_proofs) = 
                    self.parse_pcd_witness(&extracted);
                
                // Add vertex to extracted graph
                extracted_vertices.push(PCDVertex {
                    w_loc,
                    incoming_messages: incoming_messages.clone(),
                });
                
                // Add incoming messages to next level
                for (msg, prf) in incoming_messages.iter().zip(incoming_proofs.iter()) {
                    if !self.is_base_case(msg) {
                        next_level.push((msg.clone(), prf.clone()));
                    }
                }
            }
            
            current_level = next_level;
        }
        
        // Reconstruct DAG from extracted vertices
        self.reconstruct_dag(extracted_vertices)
    }
}
```

### 8. AROM Emulation and Lifting Component

#### 8.1 AROM Emulator

**Purpose**: Emulate AROM (wo, vco) using only ROM

**Mathematical Foundation**:
- AROM = (ro, wo, vco) where wo(x) := B^ro(x, μ_x) and vco is low-degree extension
- Emulator M is stateful (O, S)-emulator that simulates (wo, vco) using ro
- Security lifting: ROM properties preserved in AROM

**Data Structures**:
```rust
struct AROMEmulator<F: Field> {
    /// Random oracle
    ro: RandomOracle<Vec<F>, F>,
    
    /// Witness computation algorithm B
    witness_computer: Box<dyn Fn(&[F], &[F], &mut RandomOracle<Vec<F>, F>) -> Vec<F>>,
    
    /// Low-degree extension for verification oracle
    vco_polynomial: MultilinearPolynomial<F>,
    
    /// Degree bound
    degree_bound: usize,
    
    /// State for stateful emulation
    emulator_state: EmulatorState<F>,
}

struct EmulatorState<F: Field> {
    /// Cached witness oracle queries
    wo_cache: HashMap<Vec<F>, Vec<F>>,
    
    /// Cached verification oracle queries
    vco_cache: HashMap<Vec<F>, F>,
}

impl<F: Field> AROMEmulator<F> {
    /// Query witness oracle (emulated)
    fn query_wo(&mut self, x: &[F]) -> Vec<F> {
        if let Some(cached) = self.emulator_state.wo_cache.get(x) {
            return cached.clone();
        }
        
        // Sample μ_x uniformly
        let mu_x = self.sample_uniform(x.len());
        
        // Compute wo(x) := B^ro(x, μ_x)
        let result = (self.witness_computer)(x, &mu_x, &mut self.ro);
        
        self.emulator_state.wo_cache.insert(x.to_vec(), result.clone());
        result
    }
    
    /// Query verification oracle (emulated)
    fn query_vco(&mut self, x: &[F]) -> F {
        if let Some(cached) = self.emulator_state.vco_cache.get(x) {
            return *cached;
        }
        
        // Evaluate low-degree extension
        let result = self.vco_polynomial.evaluate(x);
        
        self.emulator_state.vco_cache.insert(x.to_vec(), result);
        result
    }
    
    /// Verify emulator correctness
    fn verify_emulation(&self) -> bool {
        // Check that vco is low-degree extension
        self.vco_polynomial.degree() <= self.degree_bound
    }
}
```

#### 8.2 Security Lifting

**Purpose**: Lift ROM security properties to AROM

**Lifting Theorems**:
```rust
struct SecurityLifting<F: Field, G: Group> {
    /// Emulator for AROM
    emulator: AROMEmulator<F>,
}

impl<F: Field, G: Group> SecurityLifting<F, G> {
    /// Lift signature scheme security (Theorem 9)
    fn lift_signature_security<Sig: SignatureScheme<G>>(
        &self,
        rom_signature: &Sig,
    ) -> Result<AROMSignature<Sig>, LiftingError> {
        // If Σ has EU-CMA in ROM, then Σ has EU-CMA in AROM
        // using emulator M
        
        // Construct AROM signature by replacing ROM with AROM emulation
        Ok(AROMSignature {
            base_scheme: rom_signature.clone(),
            emulator: self.emulator.clone(),
        })
    }
    
    /// Lift O-SNARK security (Theorem 10)
    fn lift_osnark_security<S: OSNARK<F, G, RandomOracle, SigningOracle>>(
        &self,
        rom_osnark: &S,
    ) -> Result<AROMOSNARK<S>, LiftingError> {
        // If Π has O-AdPoK in ROM, then Π has O-AdPoK in AROM
        // using emulator M
        
        Ok(AROMOSNARK {
            base_snark: rom_osnark.clone(),
            emulator: self.emulator.clone(),
        })
    }
}
```

### 9. Concrete Instantiations Component

#### 9.1 Groth16 Instantiation

**Purpose**: Modify Groth16 to work in AGM+AROM framework

**Modifications**:
1. Prover queries (A, B, C) to ROM and outputs (A, B, C, r)
2. Verifier checks Groth16 verification and oracle response correctness

**Implementation**:
```rust
struct ModifiedGroth16<F: Field, G: Group> {
    /// Standard Groth16 parameters
    proving_key: Groth16ProvingKey<G>,
    verifying_key: Groth16VerifyingKey<G>,
    
    /// Group parser for oracle forcing
    group_parser: GroupParser<G, F>,
}

impl<F: Field, G: Group> RelativizedSNARK<F, G, RandomOracle> for ModifiedGroth16<F, G> {
    fn prove(
        &self,
        ipk: &Self::IndexerKey,
        statement: &Self::Statement,
        witness: &Self::Witness,
        oracle: &mut RandomOracle
    ) -> Self::Proof {
        // Standard Groth16 prover computation
        let (a, b, c) = self.compute_groth16_proof(ipk, statement, witness);
        
        // Query oracle with (A, B, C)
        let query = self.serialize_abc(&a, &b, &c);
        let r = oracle.query(query);
        
        // Output (A, B, C, r)
        Groth16Proof { a, b, c, oracle_response: r }
    }
    
    fn verify(
        &self,
        ivk: &Self::VerifierKey,
        statement: &Self::Statement,
        proof: &Self::Proof,
        oracle: &mut RandomOracle
    ) -> bool {
        // Check standard Groth16 verification
        if !self.verify_groth16_pairing(ivk, statement, &proof.a, &proof.b, &proof.c) {
            return false;
        }
        
        // Check oracle response correctness
        let query = self.serialize_abc(&proof.a, &proof.b, &proof.c);
        let expected_response = oracle.query(query);
        
        proof.oracle_response == expected_response
    }
}
```

#### 9.2 KZG with BLS Signatures

**Purpose**: Prove KZG extraction works with BLS signing oracle

**Mathematical Foundation**:
- Adversary has access to H: M → G_1 and signing oracle O_sk
- BLS signature: σ = H(m)^sk
- Signing queries Q_σ = {(g_i, σ_i)} where σ_i = g_i^sk
- If adversary outputs commitment with non-zero δ coefficient, reduce to discrete log

**Implementation**:
```rust
struct KZGWithBLS<F: Field, G1: Group, G2: Group> {
    /// KZG commitment scheme
    kzg: KZGCommitment<F, G1, G2>,
    
    /// BLS signature scheme
    bls: BLSSignature<G1>,
}

impl<F: Field, G1: Group, G2: Group> KZGWithBLS<F, G1, G2> {
    /// Extract polynomial in presence of BLS signing oracle
    fn extract_with_bls(
        &self,
        commitment: &G1,
        signing_queries: &[(G1, G1)],  // Q_σ = {(g_i, σ_i)}
        group_representation: &GroupRepresentation<F, G1>
    ) -> Result<Polynomial<F>, ExtractionError> {
        // Parse group representation: C = Σ γ_i · crs_i + Σ δ_j · σ_j
        let (gamma_coeffs, delta_coeffs) = self.parse_representation(
            commitment,
            group_representation,
            signing_queries
        );
        
        // Check if any δ_j ≠ 0
        if delta_coeffs.iter().any(|&d| d != F::zero()) {
            // Non-zero δ implies discrete log break
            return Err(ExtractionError::DiscreteLogBreak);
        }
        
        // Extract polynomial from γ coefficients
        let polynomial = self.kzg.extract_polynomial(&gamma_coeffs);
        Ok(polynomial)
    }
}
```

#### 9.3 KZG with Schnorr Signatures

**Purpose**: Prove KZG extraction works with Schnorr signing oracle

**Mathematical Foundation**:
- Adversary has access to H: G × M → Z_p and signing oracle O_sk
- Schnorr signature: (R, z) where R = g^r, e = H(R, m), z = r + e·sk
- Signing queries Q_σ = {(R_i, z_i)} satisfying R_i · vk^e_i · g^(-z_i) = 1
- Substitute R_i dependencies to get representation in (g, vk) only

**Implementation**:
```rust
struct KZGWithSchnorr<F: Field, G: Group> {
    /// KZG commitment scheme
    kzg: KZGCommitment<F, G, G>,
    
    /// Schnorr signature scheme
    schnorr: SchnorrSignature<F, G>,
}

impl<F: Field, G: Group> KZGWithSchnorr<F, G> {
    /// Extract polynomial in presence of Schnorr signing oracle
    fn extract_with_schnorr(
        &self,
        commitment: &G,
        signing_queries: &[(G, F)],  // Q_σ = {(R_i, z_i)}
        group_representation: &GroupRepresentation<F, G>
    ) -> Result<Polynomial<F>, ExtractionError> {
        // Parse representation: C = Σ γ_i · crs_i + Σ δ_j · R_j
        let (gamma_coeffs, delta_coeffs, r_indices) = self.parse_representation_with_r(
            commitment,
            group_representation,
            signing_queries
        );
        
        // Substitute R_i = g^z_i · vk^(-e_i) for each R_i dependency
        let substituted_repr = self.substitute_r_dependencies(
            &gamma_coeffs,
            &delta_coeffs,
            &r_indices,
            signing_queries
        );
        
        // Now representation is in terms of (g, vk, crs) only
        // Check if vk coefficient is non-zero
        if substituted_repr.vk_coeff != F::zero() {
            // Non-zero vk coefficient implies discrete log break
            return Err(ExtractionError::DiscreteLogBreak);
        }
        
        // Extract polynomial from crs coefficients
        let polynomial = self.kzg.extract_polynomial(&substituted_repr.crs_coeffs);
        Ok(polynomial)
    }
    
    /// Substitute R_i = g^z_i · vk^(-e_i)
    fn substitute_r_dependencies(
        &self,
        gamma_coeffs: &[F],
        delta_coeffs: &[F],
        r_indices: &[usize],
        signing_queries: &[(G, F)]
    ) -> SubstitutedRepresentation<F> {
        let mut g_coeff = F::zero();
        let mut vk_coeff = F::zero();
        let mut crs_coeffs = gamma_coeffs.to_vec();
        
        for (i, &delta) in delta_coeffs.iter().enumerate() {
            let r_idx = r_indices[i];
            let (r, z) = &signing_queries[r_idx];
            
            // R_i = g^z_i · vk^(-e_i)
            let e = self.compute_schnorr_challenge(r);
            
            // Add δ_i · z_i to g coefficient
            g_coeff += delta * z;
            
            // Add -δ_i · e_i to vk coefficient
            vk_coeff -= delta * e;
        }
        
        SubstitutedRepresentation {
            g_coeff,
            vk_coeff,
            crs_coeffs,
        }
    }
}
```

## Data Models

### Core Data Types

```rust
/// Security parameter
type SecurityParameter = usize;

/// Field element
trait Field: Clone + PartialEq + Add + Sub + Mul + Div {
    fn zero() -> Self;
    fn one() -> Self;
    fn random() -> Self;
    fn inverse(&self) -> Option<Self>;
}

/// Group element
trait Group: Clone + PartialEq + Add + Mul<Field> {
    fn identity() -> Self;
    fn generator() -> Self;
    fn random() -> Self;
    fn serialize(&self) -> Vec<u8>;
    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializationError>;
}

/// Pairing-friendly groups
trait PairingGroup: Group {
    type G1: Group;
    type G2: Group;
    type GT: Group;
    
    fn pairing(g1: &Self::G1, g2: &Self::G2) -> Self::GT;
}
```

### Statement and Witness Types

```rust
/// IVC statement
struct IVCStatement<F: Field> {
    /// Verifier key
    ivk: Vec<u8>,
    
    /// Initial state
    z_0: Vec<F>,
    
    /// Current state
    z_out: Vec<F>,
}

/// IVC witness
struct IVCWitness<F: Field, P> {
    /// Local witness
    w_loc: Vec<F>,
    
    /// Previous state
    z_in: Vec<F>,
    
    /// Previous proof
    pi_in: P,
    
    /// Oracle responses
    r: Vec<Vec<u8>>,
}

/// Aggregate signature statement
struct AggregateStatement<G: Group> {
    /// Public keys and messages
    public_keys_messages: Vec<(VerificationKey<G>, Message)>,
}

/// Aggregate signature witness
struct AggregateWitness<G: Group> {
    /// Individual signatures
    signatures: Vec<Signature<G>>,
    
    /// Oracle responses for forced queries
    oracle_responses: Vec<Vec<u8>>,
}
```

### Proof Types

```rust
/// Generic proof structure
struct Proof<G: Group> {
    /// Group elements in proof
    group_elements: Vec<G>,
    
    /// Field elements in proof
    field_elements: Vec<Vec<u8>>,
    
    /// Oracle responses (for AGM modifications)
    oracle_responses: Option<Vec<Vec<u8>>>,
}

/// Groth16 proof with oracle response
struct Groth16Proof<G: Group> {
    a: G,
    b: G,
    c: G,
    oracle_response: Vec<u8>,
}

/// IVC proof
type IVCProof<P> = P;  // Wraps underlying SNARK proof

/// Aggregate signature proof
type AggregateSignatureProof<P> = P;  // Wraps underlying O-SNARK proof
```

## Error Handling

### Error Types

```rust
#[derive(Debug, Clone)]
enum ExtractionError {
    /// Group representation missing or invalid
    InvalidGroupRepresentation,
    
    /// Oracle transcript inconsistent
    InconsistentOracleTranscript,
    
    /// Witness extraction failed
    WitnessExtractionFailed,
    
    /// Discrete log problem encountered (security reduction)
    DiscreteLogBreak,
    
    /// Circuit not satisfied
    CircuitNotSatisfied,
    
    /// Depth bound exceeded
    DepthBoundExceeded,
}

#[derive(Debug, Clone)]
enum VerificationError {
    /// Proof verification failed
    ProofVerificationFailed,
    
    /// Oracle response mismatch
    OracleResponseMismatch,
    
    /// Invalid statement
    InvalidStatement,
    
    /// Pairing check failed
    PairingCheckFailed,
}

#[derive(Debug, Clone)]
enum SetupError {
    /// Invalid security parameter
    InvalidSecurityParameter,
    
    /// Circuit compilation failed
    CircuitCompilationFailed,
    
    /// Oracle initialization failed
    OracleInitializationFailed,
}
```

### Error Handling Strategy

```rust
impl ExtractionError {
    /// Convert extraction failure to security reduction
    fn to_security_reduction<A>(&self) -> SecurityReductionAdversary<A> {
        match self {
            ExtractionError::DiscreteLogBreak => {
                // Construct discrete log adversary
                SecurityReductionAdversary::DiscreteLog
            }
            ExtractionError::WitnessExtractionFailed => {
                // Construct SNARK adversary
                SecurityReductionAdversary::SNARKBreak
            }
            _ => SecurityReductionAdversary::Unknown
        }
    }
}
```

## Testing Strategy

### Unit Testing





### Property-Based Testing

```rust
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    
    proptest! {
        #[test]
        fn test_group_representation_linearity(
            a in any::<F>(),
            b in any::<F>(),
            g1 in any::<G>(),
            g2 in any::<G>()
        ) {
            // Test that group representations respect linearity
            let y1 = g1 * a;
            let y2 = g2 * b;
            let y_sum = y1 + y2;
            
            let repr1 = vec![a];
            let repr2 = vec![b];
            let repr_sum = vec![a, b];
            
            let basis = vec![g1, g2];
            let group_repr = GroupRepresentation { basis, coefficients: vec![repr_sum.clone()], representation_map: HashMap::new() };
            
            assert!(group_repr.verify_representation(&y_sum, &repr_sum));
        }
        
        #[test]
        fn test_ivc_correctness(
            depth in 1usize..20,
            initial_state in prop::collection::vec(any::<F>(), 10)
        ) {
            // Test IVC correctness for arbitrary depth
            let mut z_current = initial_state.clone();
            let mut proof_current = None;
            
            for i in 0..depth {
                let w_i = vec![F::from(i); 5];
                let z_next = function(&z_current, &w_i);
                proof_current = Some(prove_step(&ipk, &initial_state, &z_next, &w_i, &z_current, &proof_current, &mut oracle));
                z_current = z_next;
            }
            
            assert!(verify(&ivk, &initial_state, &z_current, &proof_current.unwrap(), &mut oracle));
        }
    }
}
```

### Security Testing

```rust
#[cfg(test)]
mod security_tests {
    use super::*;
    
    #[test]
    fn test_extraction_soundness() {
        // Test that extractor succeeds when verifier accepts
        let (z_0, z_out, proof, transcript, gamma) = setup_honest_prover();
        
        let verifier = IVCVerifier::new(ivk);
        assert!(verifier.verify(&z_0, &z_out, &proof, &mut oracle));
        
        let extractor = IVCExtractor::new(pp, circuit);
        let witness_chain = extractor.extract(&z_0, &z_out, &proof, &transcript, &gamma);
        
        assert!(witness_chain.is_ok());
    }
    
    #[test]
    fn test_algebraic_adversary_enforcement() {
        // Test that non-algebraic adversaries are rejected
        let adversary_output = AlgebraicOutput {
            output_elements: vec![G::random()],
            oracle_queried_elements: vec![],
            representations: GroupRepresentation::empty(),  // Missing representations
        };
        
        assert!(!verify_algebraic(&adversary_output));
    }
    
    #[test]
    fn test_oracle_forcing_completeness() {
        // Test that oracle forcing captures all necessary group elements
        let statement = vec![G::random(), G::random()];
        let proof = vec![G::random(), G::random(), G::random()];
        
        let all_elements = extract_group_elements(&statement, &proof);
        let forced_elements = compute_oracle_forcing_set(&all_elements, &verifier_transcript);
        
        // All elements not in verifier transcript should be forced
        for elem in &all_elements {
            if !verifier_transcript.contains(elem) {
                assert!(forced_elements.contains(elem));
            }
        }
    }
}
```


## Integration with Existing Codebase

### Architecture Integration

The AGM-secure IVC implementation will integrate with the existing Neo lattice-based zkVM codebase as a new layer that provides AGM security guarantees. The integration follows a modular approach that preserves existing functionality while adding new capabilities.

#### Integration Points

```
Existing Neo Architecture:
┌─────────────────────────────────────────────────────────┐
│                  Applications Layer                      │
│         (ZkVM, Aggregate Signatures, etc.)              │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│                    SNARK Layer                           │
│    (Symphony, SpeedySpartan, Spartan++, CP-SNARK)      │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              Folding & Protocols Layer                   │
│  (Neo Folding, LatticeFold+, Hadamard Reduction, etc.) │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│           Cryptographic Primitives Layer                 │
│    (Lattice PCS, Commitment Schemes, Hash Functions)    │
└─────────────────────────────────────────────────────────┘

New AGM-Secure IVC Layer (to be added):
┌─────────────────────────────────────────────────────────┐
│              AGM-Secure IVC Applications                 │
│    (Unbounded-depth IVC, AGM Aggregate Signatures)      │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│           AGM Composition Framework                      │
│  (Oracle Forcing, Extraction Composition, Reductions)   │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              Relativized SNARK Adapters                  │
│   (Wrap existing SNARKs with AGM modifications)         │
└─────────────────────────────────────────────────────────┘
                          ↓
        [Existing SNARK Layer - Symphony, etc.]
```

### Module Structure

The new AGM-secure implementation will be organized as follows:

```
neo-lattice-zkvm/src/
├── agm/                          # New AGM module
│   ├── mod.rs                    # Module exports
│   ├── group_representation.rs   # Group representation management
│   ├── algebraic_adversary.rs    # Algebraic adversary interfaces
│   └── parser.rs                 # Group element parsing
├── oracle/                       # New oracle module
│   ├── mod.rs
│   ├── rom.rs                    # Random Oracle Model
│   ├── arom.rs                   # Arithmetized ROM
│   ├── signed_rom.rs             # Signed ROM
│   ├── transcript.rs             # Oracle transcript management
│   └── emulator.rs               # AROM emulator
├── rel_snark/                    # New relativized SNARK module
│   ├── mod.rs
│   ├── interface.rs              # rel-SNARK trait
│   ├── adapters/                 # Adapters for existing SNARKs
│   │   ├── symphony_adapter.rs   # Wrap Symphony SNARK
│   │   ├── spartan_adapter.rs    # Wrap Spartan variants
│   │   └── groth16_adapter.rs    # Groth16 (if needed)
│   └── oracle_forcing.rs         # Oracle forcing logic
├── ivc/                          # New IVC module
│   ├── mod.rs
│   ├── prover.rs                 # IVC prover with AGM modifications
│   ├── verifier.rs               # IVC verifier
│   ├── extractor.rs              # Straight-line extractor
│   ├── circuit.rs                # Recursive verification circuit
│   └── incremental_computation.rs # Incremental computation definitions
├── o_snark/                      # New O-SNARK module
│   ├── mod.rs
│   ├── interface.rs              # O-SNARK trait
│   ├── o_adpok.rs                # O-AdPoK game
│   └── kzg_security.rs           # KZG+BLS/Schnorr security
├── aggregate_sig/                # New aggregate signature module
│   ├── mod.rs
│   ├── construction.rs           # Aggregate signature construction
│   ├── circuit.rs                # Verification circuit
│   └── security.rs               # Security reductions
└── pcd/                          # New PCD module
    ├── mod.rs
    ├── transcript.rs             # PCD transcript (DAG)
    └── extractor.rs              # Breadth-first extractor
```

### Reusing Existing Components

The AGM-secure implementation will leverage existing Neo components:

#### 1. Cryptographic Primitives
```rust
// Reuse existing field and ring implementations
use crate::field::{Field, GoldilocksField, M61Field};
use crate::ring::RingElement;
use crate::polynomial::MultilinearPolynomial;

// Reuse existing commitment schemes
use crate::commitment::{CommitmentScheme, PedersenCommitment};
use crate::lattice_pcs::{LatticePCS, PCSSecurity};
```

#### 2. Hash Functions and Fiat-Shamir
```rust
// Reuse existing hash oracle for ROM implementation
use crate::fiat_shamir::{HashOracle, HashFunction};

// Extend HashOracle to implement Oracle trait
impl Oracle<Vec<u8>, Vec<u8>> for HashOracle {
    fn query(&mut self, input: Vec<u8>) -> Vec<u8> {
        self.hash(&input)
    }
    
    fn transcript(&self) -> &OracleTranscript<Vec<u8>, Vec<u8>> {
        &self.transcript
    }
}
```

#### 3. Existing SNARK Systems
```rust
// Wrap Symphony SNARK as relativized SNARK
use crate::snark::{SymphonySNARK, SymphonyProof, SymphonyParams};

pub struct SymphonyRelSNARK {
    symphony: SymphonySNARK,
    group_parser: GroupParser,
}

impl RelativizedSNARK for SymphonyRelSNARK {
    // Implement rel-SNARK interface by wrapping Symphony
    // Add oracle forcing logic
}
```

#### 4. Signature Schemes
```rust
// Extend existing signature module
use crate::applications::signatures::{SignatureScheme, PublicKey, Signature};

// Add AGM-aware signature wrapper
pub struct AGMSignatureScheme<S: SignatureScheme> {
    base_scheme: S,
    group_representation_tracker: GroupRepresentationManager,
}
```

### Usability Enhancements

#### 1. High-Level API

Provide simple, ergonomic APIs for common use cases:

```rust
// Simple IVC API
pub struct IVCBuilder<F: Field> {
    function: Box<dyn Fn(&[F], &[F]) -> Vec<F>>,
    security_level: SecurityLevel,
}

impl<F: Field> IVCBuilder<F> {
    pub fn new(function: impl Fn(&[F], &[F]) -> Vec<F> + 'static) -> Self {
        Self {
            function: Box::new(function),
            security_level: SecurityLevel::default(),
        }
    }
    
    pub fn with_security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = level;
        self
    }
    
    pub fn build(self) -> Result<IVCSystem<F>, SetupError> {
        // Setup IVC system with AGM modifications
        let pp = setup(self.security_level.lambda());
        let (ipk, ivk) = index(&pp, &self.function)?;
        
        Ok(IVCSystem {
            prover: IVCProver::new(ipk, pp),
            verifier: IVCVerifier::new(ivk),
        })
    }
}

// Usage example
let ivc = IVCBuilder::new(|z, w| {
    // Define incremental computation
    compute_next_state(z, w)
})
.with_security_level(SecurityLevel::High)
.build()?;

// Prove multiple steps
let mut state = initial_state;
let mut proof = None;
for witness in witnesses {
    proof = Some(ivc.prover.prove_step(&initial_state, &state, &witness, proof)?);
    state = compute_next_state(&state, &witness);
}

// Verify
assert!(ivc.verifier.verify(&initial_state, &state, &proof.unwrap())?);
```

#### 2. Aggregate Signature API

```rust
// Simple aggregate signature API
pub struct AggregateSignatureBuilder {
    security_level: SecurityLevel,
    signature_scheme: SignatureSchemeType,
}

impl AggregateSignatureBuilder {
    pub fn new() -> Self {
        Self {
            security_level: SecurityLevel::default(),
            signature_scheme: SignatureSchemeType::BLS,
        }
    }
    
    pub fn with_scheme(mut self, scheme: SignatureSchemeType) -> Self {
        self.signature_scheme = scheme;
        self
    }
    
    pub fn build(self) -> Result<AggregateSignatureSystem, SetupError> {
        // Setup aggregate signature system
        AggregateSignatureSystem::setup(self.security_level, self.signature_scheme)
    }
}

// Usage example
let agg_sig = AggregateSignatureBuilder::new()
    .with_scheme(SignatureSchemeType::BLS)
    .build()?;

// Aggregate signatures
let signatures = vec![
    (vk1, msg1, sig1),
    (vk2, msg2, sig2),
    // ... more signatures
];
let aggregate_proof = agg_sig.aggregate(&signatures)?;

// Verify aggregate
let public_keys_messages = signatures.iter()
    .map(|(vk, msg, _)| (vk.clone(), msg.clone()))
    .collect();
assert!(agg_sig.verify(&public_keys_messages, &aggregate_proof)?);
```

#### 3. Configuration Integration

Extend existing configuration system:

```rust
// Extend NeoConfig with AGM settings
#[derive(Clone, Debug)]
pub struct AGMConfig {
    /// Enable AGM security checks
    pub enable_agm: bool,
    
    /// Oracle forcing strategy
    pub oracle_forcing: OracleForcingStrategy,
    
    /// Extraction timeout (for testing)
    pub extraction_timeout: Option<Duration>,
    
    /// Enable parallel extraction for PCD
    pub parallel_extraction: bool,
}

impl Default for AGMConfig {
    fn default() -> Self {
        Self {
            enable_agm: true,
            oracle_forcing: OracleForcingStrategy::Minimal,
            extraction_timeout: None,
            parallel_extraction: true,
        }
    }
}

// Add to existing NeoConfig
pub struct NeoConfig {
    // ... existing fields
    pub agm: AGMConfig,
}
```

#### 4. Backward Compatibility

Ensure existing code continues to work:

```rust
// Existing Symphony SNARK usage remains unchanged
let symphony = SymphonySNARK::new(params);
let proof = symphony.prove(&statement, &witness)?;
assert!(symphony.verify(&statement, &proof)?);

// New AGM-secure IVC can wrap existing SNARKs
let agm_symphony = AGMSymphonyAdapter::wrap(symphony);
let ivc = IVCSystem::new(agm_symphony)?;
```

### Testing Integration

Integrate with existing test infrastructure:

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::snark::SymphonySNARK;
    use crate::applications::zkvm::ZkVMProver;
    
    #[test]
    fn test_agm_ivc_with_symphony() {
        // Test AGM IVC using Symphony as underlying SNARK
        let symphony = SymphonySNARK::new(params);
        let agm_symphony = AGMSymphonyAdapter::wrap(symphony);
        let ivc = IVCSystem::new(agm_symphony).unwrap();
        
        // Run IVC test
        // ...
    }
    
    #[test]
    fn test_aggregate_signatures_with_existing_scheme() {
        // Test aggregate signatures using existing signature scheme
        let sig_scheme = SignatureScheme::new();
        let agg_sig = AggregateSignatureSystem::with_scheme(sig_scheme).unwrap();
        
        // Run aggregate signature test
        // ...
    }
}
```

### Documentation and Examples

Provide comprehensive documentation:

```rust
/// # AGM-Secure IVC Example
///
/// This example demonstrates how to use the AGM-secure IVC system
/// to prove unbounded-depth computations.
///
/// ```rust
/// use neo_lattice_zkvm::ivc::{IVCBuilder, IVCSystem};
/// use neo_lattice_zkvm::field::GoldilocksField;
///
/// // Define incremental computation
/// fn fibonacci_step(z: &[GoldilocksField], w: &[GoldilocksField]) -> Vec<GoldilocksField> {
///     vec![z[1], z[0] + z[1]]
/// }
///
/// // Build IVC system
/// let ivc = IVCBuilder::new(fibonacci_step)
///     .with_security_level(SecurityLevel::High)
///     .build()
///     .unwrap();
///
/// // Prove 1000 Fibonacci steps
/// let mut state = vec![GoldilocksField::zero(), GoldilocksField::one()];
/// let mut proof = None;
/// for _ in 0..1000 {
///     let witness = vec![]; // No witness needed for Fibonacci
///     proof = Some(ivc.prover.prove_step(&state, &witness, proof).unwrap());
///     state = fibonacci_step(&state, &witness);
/// }
///
/// // Verify (constant time regardless of depth!)
/// assert!(ivc.verifier.verify(&initial_state, &state, &proof.unwrap()).unwrap());
/// ```
pub struct IVCSystem<F: Field> {
    // ...
}
```

### Migration Path

For users of existing Neo functionality:

1. **Phase 1**: Add AGM modules without breaking changes
2. **Phase 2**: Provide adapter wrappers for existing SNARKs
3. **Phase 3**: Add high-level APIs for IVC and aggregate signatures
4. **Phase 4**: Optimize and integrate deeply with existing optimizations

This ensures smooth adoption while maintaining backward compatibility.

## Summary

This design document provides a complete technical specification for implementing the AGM-Secure Functionalities framework. The design covers:

1. **AGM Component**: Group representation management, algebraic adversary interfaces, and representation verification
2. **Oracle Component**: ROM, AROM, and Signed ROM implementations with transcript management
3. **Relativized SNARK Component**: rel-SNARK interface, group element parsing, and oracle forcing
4. **IVC Component**: Incremental computation, prover/verifier/extractor algorithms, and recursive circuits
5. **O-SNARK Component**: Extraction with signing oracles and O-AdPoK game
6. **Aggregate Signature Component**: Construction and verification circuits
7. **PCD Extension**: DAG computation support with breadth-first extraction
8. **AROM Emulation**: Security lifting from ROM to AROM
9. **Concrete Instantiations**: Groth16, KZG+BLS, KZG+Schnorr

The design emphasizes:
- **Modularity**: Clear separation of concerns with well-defined interfaces
- **Correctness**: Rigorous adherence to mathematical foundations from the paper
- **Efficiency**: Optimizations like zero overhead for Fiat-Shamir and single Γ extraction
- **Security**: Proper handling of AGM constraints and oracle forcing


All components are designed to work together seamlessly while maintaining the security properties proven in the paper.
