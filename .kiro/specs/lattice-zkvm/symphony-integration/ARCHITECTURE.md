# Symphony Lattice zkVM - System Architecture

## Overview

This document describes the complete architecture of the Symphony Lattice zkVM implementation, showing how all components interact to provide a post-quantum secure SNARK system.

## System Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                            │
│  (zkVM, ML Proofs, Aggregate Signatures, Custom Applications)   │
└─────────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Symphony SNARK System                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   Setup      │  │    Prove     │  │   Verify     │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CP-SNARK Compiler                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ Key Gen      │  │ CP-SNARK     │  │ Final SNARK  │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Folding Protocols Layer                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ High-Arity   │  │ Single       │  │ Streaming    │         │
│  │ Folding      │  │ Instance     │  │ Prover       │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Reduction of Knowledge (RoK) Toolbox                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ Hadamard     │  │ Monomial     │  │ Range Check  │         │
│  │ Reduction    │  │ Check        │  │ Protocol     │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                Cryptographic Primitives Layer                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ Ajtai        │  │ Sumcheck     │  │ Norm         │         │
│  │ Commitment   │  │ Protocol     │  │ Decomposition│         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Algebraic Foundation Layer                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ Cyclotomic   │  │ Extension    │  │ Tensor       │         │
│  │ Rings        │  │ Fields       │  │ Elements     │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

## Component Interactions

### 1. Proof Generation Flow

```
R1CS Instances (ℓ_np)
        │
        ▼
Convert to Generalized R1CS
        │
        ▼
┌───────────────────────────────────┐
│   High-Arity Folding Protocol     │
│                                   │
│  ┌─────────────────────────────┐ │
│  │ For each instance:          │ │
│  │   Single Instance Reduction │ │
│  │   ├─ Hadamard Check         │ │
│  │   ├─ Range Proof            │ │
│  │   └─ Monomial Check         │ │
│  └─────────────────────────────┘ │
│                                   │
│  Merge Sumcheck Claims            │
│  Sample Folding Challenge β       │
│  Compute Folded Commitment c_*    │
│  Compute Folded Witness f_*       │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│      CP-SNARK Compiler            │
│                                   │
│  Generate CP-SNARK Proof π_cp     │
│  (proves folding correctness)     │
│                                   │
│  Generate Final SNARK Proof π     │
│  (proves reduced statement)       │
└───────────────────────────────────┘
        │
        ▼
Symphony Proof π_* = (π_cp, π, commitments, x_o)
```

### 2. Verification Flow

```
Symphony Proof π_*
        │
        ▼
Recompute Challenges from Transcript
        │
        ▼
┌───────────────────────────────────┐
│   Verify CP-SNARK Proof π_cp      │
│                                   │
│  ✓ Folding verification correct   │
│  ✓ Commitments well-formed        │
│  ✓ Output instance correct        │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│   Verify Final SNARK Proof π      │
│                                   │
│  ✓ Linear relation holds          │
│  ✓ Batch linear relations hold    │
└───────────────────────────────────┘
        │
        ▼
Accept/Reject
```

## Key Data Structures

### Commitment Hierarchy

```
CommitmentKey
    ├─ matrix_a: Vec<Vec<RingElement>>  // MSIS matrix A ∈ Rq^{κ×n}
    ├─ kappa: usize                      // Number of rows
    ├─ n: usize                          // Number of columns
    └─ params: AjtaiParams               // Security parameters

Commitment
    └─ value: Vec<RingElement>           // c ∈ Rq^κ

Opening
    ├─ witness: Vec<RingElement>         // f ∈ Rq^n
    └─ scalar: RingElement               // s ∈ S - S
```

### Instance Hierarchy

```
R1CSInstance
    ├─ num_constraints: usize
    ├─ num_variables: usize
    ├─ public_input: Vec<F>
    └─ matrices: (M1, M2, M3)
            │
            ▼
GeneralizedR1CSInstance
    ├─ commitment: Commitment
    ├─ public_input: Vec<Vec<F>>         // X_in ∈ Z_q^{n_in×d}
    ├─ r1cs_matrices: (M1, M2, M3)
    ├─ norm_bound: f64
    └─ block_size: usize
            │
            ▼
SingleInstanceOutput
    ├─ linear_instance: LinearInstance
    └─ batch_linear_instance: BatchLinearInstance
            │
            ▼
FoldedOutput
    ├─ linear_instance: LinearInstance
    ├─ batch_linear_instance: BatchLinearInstance
    ├─ folded_witness: FoldedWitness
    └─ message_commitments: Vec<Commitment>
            │
            ▼
OutputInstance
    ├─ linear_commitment: Commitment
    ├─ linear_evaluation_point: Vec<ExtField>
    ├─ linear_claimed_value: ExtField
    ├─ batch_linear_commitment: Commitment
    ├─ batch_linear_evaluation_point: Vec<ExtField>
    └─ batch_linear_claimed_values: Vec<TensorElement>
```

### Proof Hierarchy

```
SingleInstanceProof
    ├─ helper_commitments: Vec<Commitment>
    ├─ hadamard_proof: HadamardProof
    ├─ range_proof: RangeCheckProof
    └─ shared_challenges: SharedChallenges
            │
            ▼
HighArityFoldingProof
    ├─ single_instance_proofs: Vec<SingleInstanceProof>
    ├─ merged_sumcheck_outputs: MergedSumcheckOutputs
    └─ folding_challenge: Vec<RingElement>
            │
            ▼
CPSNARKProof
    ├─ verification_proof: Vec<u8>
    ├─ commitment_proof: Vec<u8>
    └─ output_proof: Vec<u8>
            │
            ▼
SymphonyProof
    ├─ cp_snark_proof: CPSNARKProof
    ├─ snark_proof: Vec<u8>
    ├─ message_commitments: Vec<Commitment>
    └─ output_instance: OutputInstance
```

## Protocol Execution Details

### Single Instance Reduction (Π_gr1cs)

```
Input: (instance, witness)
    │
    ▼
Step 1: Sample Shared Challenges
    ├─ Projection matrix J ← χ^{λ_pj × ℓ_h}
    ├─ Challenge vector s' ∈ K^{log(m)}
    └─ Combiner α ∈ K
    │
    ▼
Step 2: Construct Full Witness
    F^⊤ = [X_in^⊤, W^⊤] ∈ Z_q^{d×n}
    │
    ▼
Step 3: Compute Helper Commitments
    For i ∈ [k_g]:
        ├─ Extract decomposition layer H^(i)
        ├─ Compute monomial vector g^(i)
        └─ Commit: c^(i) := A·g^(i)
    │
    ▼
Step 4: Run Parallel Sumchecks
    ┌─────────────────────┬─────────────────────┐
    │  Hadamard Sumcheck  │  Monomial Sumcheck  │
    │  (log(m) rounds)    │  (log(n) rounds)    │
    │                     │                     │
    │  Share challenges:  │  (r̄, s̄, s)         │
    └─────────────────────┴─────────────────────┘
    │
    ▼
Step 5: Finalize Reductions
    ├─ Hadamard → Linear Instance
    └─ Range Proof → Batch Linear Instance
    │
    ▼
Output: (linear_instance, batch_linear_instance)
```

### High-Arity Folding (Π_fold)

```
Input: ℓ_np instances and witnesses
    │
    ▼
Step 1: Execute Parallel Π_gr1cs
    For ℓ ∈ [ℓ_np]:
        Run Π_gr1cs with shared randomness
    │
    ▼
Step 2: Merge Sumcheck Claims
    ├─ Hadamard: Σ_{b,ℓ,j} α^{(ℓ-1)·d+j-1}·f_{ℓ,j}(b) = 0
    └─ Monomial: Batched with α combiners
    │
    ▼
Step 3: Verify Evaluation Consistency
    Check all instances share evaluation point
    │
    ▼
Step 4: Sample Folding Challenge
    β ← S^{ℓ_np} where ∥S∥_op ≤ 15
    │
    ▼
Step 5: Compute Folded Commitment
    c_* := Σ_{ℓ=1}^{ℓ_np} β_ℓ·c_ℓ
    │
    ▼
Step 6: Compute Folded Witness
    f_* := Σ_{ℓ=1}^{ℓ_np} β_ℓ·f_ℓ
    │
    ▼
Step 7: Verify Norm Bounds
    ∥f_*∥_2 ≤ ℓ_np·∥S∥_op·B√(nd/ℓ_h)
    │
    ▼
Output: (folded_output, proof)
```

### Streaming Prover Algorithm

```
Input: ℓ_np instances and witnesses
    │
    ▼
Pass 1: Compute Commitments (O(n) memory)
    For each instance:
        ├─ Stream witness in chunks
        ├─ Compute partial commitments
        └─ Accumulate to full commitment
    │
    ▼
Pass 2: Streaming Sumcheck (log log(n) passes)
    For pass ∈ [log log(n)]:
        ├─ Compute evaluation table
        ├─ Stream through witnesses
        └─ Accumulate evaluations
    │
    Run sumcheck rounds using tables
    │
    ▼
Pass 3: Fold Witnesses (O(n) memory)
    For each witness:
        ├─ Stream in chunks
        ├─ Scale by folding challenge
        └─ Accumulate to folded witness
    │
    ▼
Output: (folded_output, proof)

Total Memory: O(n)
Total Passes: 2 + log log(n)
```

## Security Architecture

### Cryptographic Assumptions

```
┌─────────────────────────────────────────────────────────────┐
│                    Module-SIS Assumption                     │
│                                                              │
│  Hard to find short vector x s.t. A·x = 0 (mod q)          │
│  where A ∈ Rq^{κ×n} and ∥x∥_2 ≤ β_SIS                      │
│                                                              │
│  Security: 128 bits post-quantum                            │
│  Parameters: κ=4, n=256, β_SIS=60000                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Commitment Binding                          │
│                                                              │
│  Ajtai commitment is binding under Module-SIS               │
│  β_SIS = 4T·B_rbnd where T = ∥S∥_op ≤ 15                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Knowledge Soundness                         │
│                                                              │
│  Knowledge error: ϵ ≈ nλ_pj·d/(ℓ_h·2^141)                  │
│  Extraction: Coordinate-wise special soundness              │
│  Queries: ℓ_np + 1 in expectation                           │
└─────────────────────────────────────────────────────────────┘
```

### Challenge Set Design

```
Challenge Set S ⊆ Rq
    │
    ├─ Size: |S| = 256
    │
    ├─ Operator Norm: ∥S∥_op ≤ 15
    │
    ├─ Construction: LaBRADOR design
    │   ├─ Coefficients in {-1, 0, 1}
    │   ├─ Hamming weight: d/4
    │   └─ Deterministic generation
    │
    └─ Properties:
        ├─ Invertibility: ∥y∥_∞ < q^{1/e}/√e
        ├─ Norm bound: ∥a·b∥_∞ ≤ ∥b∥_∞
        └─ Security: Resistant to lattice attacks
```

## Performance Optimization Strategies

### 1. Streaming Prover
- **Memory:** O(n) instead of O(n·ℓ_np)
- **Passes:** 2 + log log(n) over data
- **Parallelization:** Multi-core support
- **Chunk Size:** Configurable based on memory budget

### 2. Sumcheck Optimization
- **Prover:** O(n) field operations per round
- **Verifier:** O(D) field operations per round
- **Batching:** Random linear combination of claims
- **Evaluation Tables:** Cache-friendly access patterns

### 3. Commitment Optimization
- **Precomputation:** Setup matrices during key generation
- **Batching:** Commit to multiple values simultaneously
- **Streaming:** Process large witnesses in chunks
- **Parallelization:** Independent commitment computations

### 4. Folding Optimization
- **Shared Randomness:** Reduce challenge generation overhead
- **Parallel Execution:** Process instances concurrently
- **Lazy Evaluation:** Compute only when needed
- **Memory Pooling:** Reuse allocated memory

## Parameter Selection Guide

### Security Level: 128-bit Post-Quantum

```
Ring Degree (d):
    ├─ d = 64:  Standard, balanced performance
    └─ d = 128: Higher security margin

Field Modulus (q):
    ├─ Goldilocks (2^64 - 2^32 + 1): Fast arithmetic
    └─ Mersenne 61 (2^61 - 1): Smaller proofs

Folding Arity (ℓ_np):
    ├─ 1024 (2^10):  Small batches, fast verification
    ├─ 4096 (2^12):  Balanced, recommended default
    ├─ 8192 (2^13):  Large batches, better amortization
    └─ 65536 (2^16): Maximum throughput

Module-SIS Parameters:
    ├─ κ = 4:       Number of commitment rows
    ├─ n = 256:     Number of commitment columns
    └─ β_SIS:       4T·B_rbnd where T = 15

Projection Security:
    └─ λ_pj = 256:  Projection security parameter
```

### Trade-offs

```
Proof Size vs Verification Time:
    ├─ Larger ℓ_np → Smaller proof per instance
    └─ Larger ℓ_np → Longer verification time

Memory vs Speed:
    ├─ Streaming prover: O(n) memory, slower
    └─ Standard prover: O(n·ℓ_np) memory, faster

Security vs Performance:
    ├─ Post-quantum: Larger proofs, higher security
    └─ Classical: Smaller proofs, lower security
```

## Integration Points

### Application Integration

```rust
// 1. Setup
let params = SymphonyParams::default_post_quantum();
let snark = SymphonySNARK::setup(params)?;

// 2. Convert application constraints to R1CS
let instances: Vec<R1CSInstance> = application.to_r1cs();
let witnesses: Vec<Vec<Field>> = application.witnesses();

// 3. Generate proof
let proof = snark.prove(&instances, &witnesses)?;

// 4. Verify proof
let valid = snark.verify(&instances, &proof)?;
```

### Custom Applications

```rust
// zkVM Integration
impl ZkVM {
    fn prove_execution(&self, program: &Program) -> Result<Proof> {
        let r1cs = self.compile_to_r1cs(program)?;
        let witness = self.generate_witness(program)?;
        self.snark.prove(&[r1cs], &[witness])
    }
}

// ML Proof Integration
impl MLProver {
    fn prove_inference(&self, model: &Model, input: &Tensor) -> Result<Proof> {
        let r1cs = self.model_to_r1cs(model)?;
        let witness = self.inference_witness(model, input)?;
        self.snark.prove(&[r1cs], &[witness])
    }
}
```

## Conclusion

The Symphony Lattice zkVM provides a complete, production-ready implementation of a post-quantum secure SNARK system with:

- **Modular Architecture:** Clean separation of concerns
- **Comprehensive Security:** 128-bit post-quantum security
- **High Performance:** Optimized for throughput and memory
- **Flexible Configuration:** Multiple parameter presets
- **Production Quality:** Extensive testing and error handling

All components work together seamlessly to provide efficient proof generation and verification for a wide range of applications.
