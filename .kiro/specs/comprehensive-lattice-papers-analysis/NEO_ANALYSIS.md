# NEO: Lattice-based Folding Scheme for CCS over Small Fields

## Paper Overview
**Authors:** Wilson Nguyen, Srinath Setty  
**Focus:** Lattice-based folding scheme supporting small prime fields  
**Key Innovation:** Pay-per-bit commitment costs and native small field support (Goldilocks, M61)

## Core Components

### 1. Folding-Friendly Lattice Commitments
**Key Innovation:** Ajtai commitments with pay-per-bit costs

**Mapping Strategy:**
- Maps vectors from small field Fq to cyclotomic polynomial ring elements
- Cyclotomic polynomial defined over Fq
- Commits via Ajtai's commitment scheme

**Pay-Per-Bit Property:**
- Committing to n-bit vector: 64x cheaper than n 64-bit values
- Scales with actual bit-width of witness elements
- Enables efficient small field arithmetic

### 2. Matrix Commitment Scheme
**Neo's Solution Part 1:**
- Transforms vector of field elements into matrix
- Commits to matrix representation
- Provides linear homomorphism for folding

**Properties:**
- Binding under Module SIS assumption
- Linear homomorphic for multilinear evaluation claims
- Supports arbitrary small prime fields

### 3. Linear Homomorphism for Folding
**Neo's Solution Part 2:**
- Treats committed vector as multilinear polynomial
- Polynomial in evaluation form over Boolean hypercube
- Supports folding of evaluation claims

**Folding Property:**
- Given β ≥ 2 commitments with evaluations {(Ci, r, yi)}i∈[β]
- Witnesses {wi}i∈[β] satisfy: Ci commits to wi and w̃i(r) = yi
- Folding reduces to single commitment and evaluation claim

### 4. CCS Reduction (ΠCCS)
**Constraint System Support:**
- Generalizes R1CS, Plonkish, and AIR
- Supports lookup checks
- Reduces CCS to committed linear relations

### 5. Random Linear Combination (ΠRLC)
**Folding Step:**
- Verifier samples low-norm vector β
- Prover combines witnesses using β
- Verifier combines instances using β
- Preserves committed linear relation by linearity

### 6. Decomposition Reduction (ΠDEC)
**Witness Decomposition:**
- Decomposes witness into low-norm components
- Enables efficient norm verification
- Supports arbitrary field elements

## Missing Components & Required Implementations

### A. Theoretical Foundations

1. **Pay-Per-Bit Commitment Proof**
   - Missing: Formal proof of pay-per-bit property
   - Required: Detailed analysis of commitment costs
   - Acceptance Criteria:
     - Commitment cost: O(bit-width) field operations
     - Proof: 64x speedup for bit vectors vs. 64-bit values
     - Binding: negl(λ) under Module SIS

2. **Linear Homomorphism Verification**
   - Missing: Formal proof of linear homomorphism
   - Required: Detailed multilinear polynomial analysis
   - Acceptance Criteria:
     - Homomorphism: C(w1 + w2) = C(w1) + C(w2)
     - Evaluation preservation: w̃(r) preserved under folding
     - Soundness: negl(λ) error

3. **CCS Folding Soundness**
   - Missing: Complete soundness proof for CCS folding
   - Required: Formal analysis of constraint preservation
   - Acceptance Criteria:
     - Soundness error: negl(λ)
     - Supports arbitrary CCS relations
     - Handles lookup constraints

### B. Protocol Specifications

1. **Small Field Instantiation**
   - Missing: Complete protocol for Goldilocks field
   - Required: Detailed parameter selection
   - Acceptance Criteria:
     - Support q = 2^64 - 2^32 + 1 (Goldilocks)
     - Support q = 2^61 - 1 (Mersenne 61)
     - Efficient field arithmetic
     - No embedding overhead

2. **Multilinear Evaluation Folding**
   - Missing: Complete protocol specification
   - Required: Detailed sumcheck integration
   - Acceptance Criteria:
     - Single sumcheck invocation
     - Verifier: O(log n) field operations
     - Prover: O(n) field operations
     - Proof size: O(log n) elements

3. **Lookup Constraint Support**
   - Missing: Complete protocol for lookup checks
   - Required: Integration with CCS folding
   - Acceptance Criteria:
     - Support arbitrary lookup tables
     - Verifier: O(log n) field operations
     - Prover: O(n) field operations
     - Proof size: O(log n) elements

### C. Implementation Requirements

1. **Ajtai Commitment Implementation**
   - Missing: Efficient Ajtai commitment for small fields
   - Required: Optimized matrix commitment
   - Acceptance Criteria:
     - Commitment: O(n) field operations
     - Verification: O(log n) field operations
     - Constant-time operations
     - Hardware acceleration support

2. **Sumcheck Protocol Optimization**
   - Missing: Optimized sumcheck for small fields
   - Required: Dynamic programming-based prover
   - Acceptance Criteria:
     - Prover: O(n) field operations
     - Memory: O(n) for witness storage
     - Parallelizable across variables
     - Support extension fields

3. **Folding Verifier Circuit**
   - Missing: Concrete R1CS/Plonkish circuit
   - Required: Optimized gate count
   - Acceptance Criteria:
     - Verifier circuit: O(ℓ) field operations
     - O(1) commitment combinations
     - Support arbitrary ℓ instances
     - Constant-time operations

### D. Cryptographic Assumptions

1. **Module SIS Hardness**
   - Missing: Formal hardness assumption
   - Required: Security parameter selection
   - Acceptance Criteria:
     - Formal hardness assumption
     - Reduction from standard lattice problems
     - Security loss: poly(λ)

2. **Small Field Compatibility**
   - Missing: Analysis of security with small fields
   - Required: Formal security proof
   - Acceptance Criteria:
     - Security: 128 bits for 64-bit fields
     - No embedding overhead
     - Efficient extension field operations

### E. Performance Optimization

1. **Small Field Arithmetic**
   - Missing: Optimized field operations
   - Required: SIMD-accelerated arithmetic
   - Acceptance Criteria:
     - 10-100x speedup vs. 256-bit fields
     - Constant-time operations
     - Support vector instructions

2. **Commitment Cost Reduction**
   - Missing: Techniques to further reduce commitment costs
   - Required: Bit-width aware optimizations
   - Acceptance Criteria:
     - Pay-per-bit property verified
     - 64x speedup for bit vectors
     - Compression ratio: ≥ 2x vs. LatticeFold

3. **Prover Parallelization**
   - Missing: Detailed parallel algorithm
   - Required: Work distribution strategy
   - Acceptance Criteria:
     - Linear speedup with p processors
     - Communication overhead: O(log p)
     - Memory: O(n/p) per processor

### F. Comparison with LatticeFold

1. **Advantages Over LatticeFold**
   - Missing: Detailed comparison analysis
   - Required: Benchmark against LatticeFold
   - Acceptance Criteria:
     - No packing overhead
     - Pay-per-bit commitment costs
     - Single sumcheck invocation
     - Support Goldilocks field

2. **Efficiency Improvements**
   - Missing: Concrete performance metrics
   - Required: Detailed benchmarks
   - Acceptance Criteria:
     - 4x speedup vs. LatticeFold (extension field)
     - 10-100x speedup vs. polynomial ring ops
     - Proof size: comparable or better
     - Verifier: < 10 ms

### G. Application Implementations

1. **IVC/PCD Construction**
   - Missing: Complete IVC/PCD scheme
   - Required: Recursive folding protocol
   - Acceptance Criteria:
     - Support arbitrary computation
     - Verifier: O(log n) field operations
     - Prover: O(n) field operations
     - Proof compression

2. **Lookup and Memory Support**
   - Missing: Complete lookup/memory protocols
   - Required: Integration with CCS folding
   - Acceptance Criteria:
     - Support read-only memory
     - Support read-write memory
     - Verifier: O(log n) field operations
     - Prover: O(n) field operations

## Acceptance Criteria Summary

### Functional Requirements
- [ ] Pay-per-bit commitment costs
- [ ] Support small prime fields (Goldilocks, M61)
- [ ] Native CCS folding (no packing)
- [ ] Single sumcheck invocation
- [ ] Lookup constraint support
- [ ] Memory operation support

### Performance Requirements
- [ ] Commitment: O(n) field operations
- [ ] Verifier: O(log n) field operations
- [ ] Prover: O(n) field operations
- [ ] Proof size: O(log n) elements
- [ ] 4x speedup vs. LatticeFold
- [ ] 10-100x speedup vs. polynomial ring ops

### Security Requirements
- [ ] Knowledge soundness: negl(λ) error
- [ ] Module SIS hardness
- [ ] 128-bit security for 64-bit fields
- [ ] Constant-time operations
- [ ] Post-quantum security

### Testing Requirements
- [ ] Property-based tests for folding
- [ ] Soundness verification across field sizes
- [ ] Performance benchmarks vs. LatticeFold
- [ ] Security proofs formalized
- [ ] Hardware acceleration validation
- [ ] Lookup constraint verification
