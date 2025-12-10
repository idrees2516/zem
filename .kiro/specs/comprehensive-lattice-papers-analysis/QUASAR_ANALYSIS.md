# QUASAR: Sublinear Accumulation Schemes for Multiple Instances

## Paper Overview
**Authors:** Tianyu Zheng, Shang Gao, Yu Guo, Bin Xiao  
**Focus:** Multi-instance accumulation schemes with sublinear verifier complexity  
**Key Innovation:** Reduces CRC (Commitment Random linear Combination) operations from linear to quasi-linear

## Core Components

### 1. Multi-Instance IVC Framework
- **Definition:** Extends standard IVC to handle ℓ predicate instances and one accumulator per step
- **Key Property:** Prover can accumulate multiple instances simultaneously
- **Benefit:** Reduces total recursive steps while maintaining efficiency

### 2. Multi-Instance Accumulation Scheme
**Definition 2 Components:**
- **Prover:** ACC.P({xk}k∈[ℓ], π, acc) → (acc', pf)
- **Verifier:** ACC.V({xk}k∈[ℓ], π.x, acc.x) → b
- **Decider:** ACC.D(acc) → b

### 3. Novel Multi-Cast Reduction (NIRmulticast)
**Key Innovation:** Shifts combining ℓ committed instances from fold to cast phase
- Sends union polynomial commitment C∪ of multilinear extension
- Partial evaluation at Y = τ ∈ F^(log ℓ)
- Verifier checks: w̃∪(τ, rx) = w̃(rx) at random rx

**Soundness Error:** log n / |F|

### 4. 2-to-1 Reduction (NIRfold)
- Built from oracle batching reduction IORbatch
- Reduces two evaluation claims to one via sum-check
- Achieves sublinear verifier complexity

## Missing Components & Required Implementations

### A. Theoretical Gaps

1. **Soundness Analysis for Multi-Instance Relations**
   - Missing: Formal proof that multi-predicate tuple accumulation preserves soundness
   - Required: Detailed soundness error analysis for ℓ > 2 instances
   - Acceptance Criteria:
     - Soundness error ≤ negl(λ) for all ℓ ∈ poly(λ)
     - Proof must handle arbitrary instance distributions

2. **Knowledge Soundness of Multi-Cast Reduction**
   - Missing: Extractor construction for NIRmulticast
   - Required: Formal knowledge soundness proof
   - Acceptance Criteria:
     - Extractor runs in poly(λ, ℓ) time
     - Extraction probability ≥ 1 - negl(λ)

3. **Sublinear Verifier Complexity Proof**
   - Missing: Formal complexity analysis showing O(log ℓ) RO queries
   - Required: Detailed breakdown of verifier operations
   - Acceptance Criteria:
     - Verifier time: O(log ℓ) RO + O(1) group operations
     - Proof size: polylog(ℓ) + O(d) where d = max degree

### B. Protocol Specifications

1. **Concrete Instantiation with Plonkish Constraints**
   - Missing: Detailed protocol for Plonkish constraint systems
   - Required: Specification of constraint reduction to Ξlin
   - Acceptance Criteria:
     - Support arbitrary Plonkish relations
     - Verifier complexity remains O(log ℓ)

2. **Elliptic Curve Instantiation (Quasar-curve)**
   - Missing: Complete protocol specification
   - Required: Detailed commitment scheme integration
   - Acceptance Criteria:
     - O(1) group operations in verification
     - O(log ℓ) random oracle queries
     - Proof size: O(log ℓ) group elements

3. **Linear Code Instantiation (Quasar-code)**
   - Missing: Full protocol with code-based commitments
   - Required: Integration with linear-time-encodable codes
   - Acceptance Criteria:
     - Post-quantum security
     - Verifier: O(log(1/ρ)/λ · (log n + log ℓ)) RO queries
     - Proof size: polylog(n, ℓ)

### C. Implementation Requirements

1. **Multi-Instance Accumulation Prover**
   - Missing: Efficient implementation of NIRmulticast
   - Required: Optimized polynomial commitment and evaluation
   - Acceptance Criteria:
     - Linear-time prover complexity O(n)
     - Memory: O(n) for witness storage
     - Parallelizable across instances

2. **Recursive Circuit Implementation**
   - Missing: Concrete R1CS/Plonkish circuit for folding verifier
   - Required: Optimized gate count for CRC operations
   - Acceptance Criteria:
     - O(ℓ) field operations per step
     - O(1) CRC operations per step
     - Total recursive gates: O(√N) for N steps

3. **Parallelization Framework**
   - Missing: Detailed parallel proving algorithm
   - Required: Work distribution strategy for multi-instance accumulation
   - Acceptance Criteria:
     - Linear speedup with p processors for p ≤ ℓ
     - Communication overhead: O(log p) per round

### D. Security Analysis

1. **Post-Quantum Security Proof**
   - Missing: Formal reduction from code-based assumptions
   - Required: Security proof for Quasar-code instantiation
   - Acceptance Criteria:
     - Reduction to linear code hardness
     - Security loss: poly(λ, ℓ)

2. **Soundness Gap Analysis**
   - Missing: Formal analysis of soundness gaps in multi-instance setting
   - Required: Proof that gaps don't accumulate across steps
   - Acceptance Criteria:
     - Total soundness error: negl(λ) after N steps
     - Gap per step: ≤ 1/poly(λ, ℓ)

### E. Optimization & Performance

1. **CRC Operation Optimization**
   - Missing: Concrete optimization techniques for commitment combinations
   - Required: Hardware-accelerated implementations
   - Acceptance Criteria:
     - 10-100x speedup over naive implementation
     - Constant-time operations for security

2. **Proof Size Optimization**
   - Missing: Techniques to reduce proof size below current bounds
   - Required: Compression strategies for multi-instance proofs
   - Acceptance Criteria:
     - Proof size: O(log ℓ) + O(d) elements
     - Compression ratio: ≥ 2x vs. sequential accumulation

## Acceptance Criteria Summary

### Functional Requirements
- [ ] Multi-instance accumulation for ℓ ≥ 2 instances
- [ ] Sublinear verifier complexity in ℓ
- [ ] Support for Plonkish and R1CS constraints
- [ ] Parallelizable prover algorithm
- [ ] Post-quantum security option

### Performance Requirements
- [ ] Verifier: O(log ℓ) RO queries + O(1) group ops
- [ ] Prover: Linear time O(n) per instance
- [ ] Proof size: polylog(ℓ) + O(d)
- [ ] Recursive circuit: O(√N) total gates for N steps
- [ ] CRC operations: O(1) per step (vs. O(ℓ) previously)

### Security Requirements
- [ ] Knowledge soundness: negl(λ) error
- [ ] Soundness gap: ≤ 1/poly(λ, ℓ)
- [ ] Post-quantum security for code-based variant
- [ ] Constant-time operations for sensitive computations

### Testing Requirements
- [ ] Property-based tests for multi-instance accumulation
- [ ] Soundness verification across varying ℓ
- [ ] Performance benchmarks vs. ProtoGalaxy, KiloNova
- [ ] Security proofs formalized in proof assistant
