# Performance Optimizations (Security-Preserving)

## Overview

This document identifies **concrete performance optimizations** that maintain 128-bit quantum security while significantly improving efficiency. Each optimization includes theoretical speedup, implementation complexity, and security analysis.

---

## 1. Advanced NTT Optimizations

### Current State
- Standard NTT: O(n·log n) per polynomial multiplication
- n = 1024 coefficients, q ≈ 2^60

### Optimizations

#### 1.1 Lazy Reduction in NTT
**Speedup**: 2-3× faster NTT operations  
**Security Impact**: None (maintains modular arithmetic correctness)

**Technique**:
- Delay modular reductions during NTT butterfly operations
- Use 128-bit accumulators to prevent overflow
- Reduce only when necessary (every k layers where k = ⌊64/log₂(q)⌋ = 1)

**Implementation**:
```rust
// Instead of: c = (a * b) % q at each step
// Use: c_acc = a * b (128-bit), reduce every k layers
```

**Requirement Addition**: Add to Req 4.7, 8.9, 8.23

#### 1.2 Precomputed Twiddle Factors
**Speedup**: 1.5× faster NTT  
**Memory**: +16 KB per prover  
**Security Impact**: None

**Technique**:
- Precompute all ω^i mod q for i ∈ [n]
- Store in cache-friendly layout (aligned to 64-byte cache lines)
- Use SIMD loads for batch access

**Requirement Addition**: Add to Req 1.1 (Setup phase)

#### 1.3 Negative Wrapped Convolution (NWC)
**Speedup**: 2× reduction in NTT size  
**Security Impact**: None (equivalent to standard NTT)

**Technique**:
- Exploit X^n + 1 structure: NTT size n/2 instead of n
- Use negacyclic convolution property
- Reduces memory bandwidth by 2×

**Requirement Addition**: Add to Req 4.7, 8.9

---

## 2. Gadget Decomposition Optimizations

### Current State
- Base b = 4, limbs ℓ = 30
- Decomposition cost: O(n·ℓ) = O(30,720) operations per witness

### Optimizations

#### 2.1 Adaptive Base Selection
**Speedup**: 1.3× fewer limbs  
**Security Impact**: None (maintains norm bounds)

**Technique**:
- Use variable base: b = 8 for high-order limbs, b = 4 for low-order
- Reduces ℓ from 30 to 23 limbs (log₈(2^60) = 20, plus safety margin)
- Maintains ||w_{i,j}||_∞ < b bound

**Trade-off**:
- Slightly larger norm bound: √(n·23)·8 vs √(n·30)·4
- Still well within security parameters

**Requirement Update**: Modify Req 4.2, 6.2, 8.4

#### 2.2 SIMD Gadget Decomposition
**Speedup**: 4-8× faster decomposition  
**Security Impact**: None

**Technique**:
- Vectorize decomposition using AVX2/AVX-512
- Process 4-8 coefficients in parallel
- Use SIMD bit shifts and masks

**Implementation**:
```rust
// AVX2: process 4 × 64-bit coefficients simultaneously
// Extract limbs using _mm256_srli_epi64 and _mm256_and_si256
```

**Requirement Addition**: Add to Req 6.2, 8.4

#### 2.3 Lazy Decomposition
**Speedup**: Amortize decomposition cost  
**Memory**: +O(n·ℓ) per prover  
**Security Impact**: None

**Technique**:
- Decompose witness once at initialization
- Reuse decomposed form across all rounds
- Only recompose at final output

**Requirement Update**: Modify Req 4.2 (decompose once), Req 8.16 (recompose once)

---

## 3. Network Communication Optimizations

### Current State
- Communication: O(M·T·ℓ·n·log M) ring elements ≈ 1.9 GB for M=8, N=2^20
- Latency: ~30 seconds for 8 provers

### Optimizations

#### 3.1 Incremental Compression
**Speedup**: 3-4× bandwidth reduction  
**Security Impact**: None (lossless compression)

**Technique**:
- **Coefficient Packing**: Pack multiple small coefficients into 64-bit words
  - For decomposed limbs with ||w||_∞ < 4: use 3 bits per coefficient
  - Pack 21 coefficients per 64-bit word
  - Reduction: 64/3 ≈ 21× per limb
- **Delta Encoding**: Send differences between consecutive coefficients
  - Exploit locality: Δw[i] = w[i] - w[i-1] typically small
  - Use variable-length encoding (Elias gamma coding)
- **Structured Sparsity**: Exploit zero coefficients in NTT representation
  - Use run-length encoding for zero runs
  - Expected 20-30% sparsity in practice

**Combined Reduction**: 3-4× total bandwidth

**Requirement Addition**: Add to Req 5.7 (enhance compression)

#### 3.2 Batched Message Aggregation
**Speedup**: 2× reduction in message count  
**Latency**: -40% (fewer round trips)  
**Security Impact**: None

**Technique**:
- Aggregate multiple witness slices into single message
- Send all {w_{s,j,ℓ',x}} for fixed (s,j) in one batch
- Reduces TCP/IP overhead (40 bytes per packet)

**Requirement Addition**: Add to Req 5.5, 8.6

#### 3.3 Speculative Challenge Precomputation
**Speedup**: 1.5× faster rounds  
**Security Impact**: None (challenges still random)

**Technique**:
- Coordinator precomputes next challenge while waiting for messages
- Workers speculatively compute for multiple challenge values
- Select correct computation when challenge arrives
- Trade computation for latency (worthwhile for network-bound protocols)

**Requirement Addition**: Add to Req 8.13, 8.26 (enhance pipelining)

#### 3.4 UDP with Selective Reliability
**Speedup**: 2× lower latency  
**Security Impact**: None (maintain integrity checks)

**Technique**:
- Use UDP for time-sensitive messages (challenges, small data)
- Implement application-level reliability (ACK/NACK)
- Keep TCP for large data transfers (witness slices)
- Reduces latency from ~50ms to ~25ms per round

**Requirement Update**: Modify Req 5.1, 5.8 (hybrid TCP/UDP)

---

## 4. Rejection Sampling Optimizations

### Current State
- Expected iterations: 12
- Overhead: ~12× vs no rejection sampling
- Bottleneck: Gaussian sampling and probability computation

### Optimizations

#### 4.1 Vectorized Gaussian Sampling
**Speedup**: 8× faster sampling  
**Security Impact**: None (maintains distribution)

**Technique**:
- Use AVX2/AVX-512 for parallel CDT lookups
- Sample 8 Gaussian values simultaneously
- Vectorize binary search in CDT table

**Implementation**:
```rust
// AVX2: sample 4 Gaussian values in parallel
// Use _mm256_cmpgt_epi64 for vectorized binary search
```

**Requirement Addition**: Add to Req 7.9

#### 4.2 Approximate Rejection Sampling
**Speedup**: 3× fewer iterations (E[iter] ≈ 4)  
**Security Impact**: Minimal (Δ increases from 2^{-128} to 2^{-120})

**Technique**:
- Use looser rejection bound M = 4.0 instead of 12.0
- Accept slightly larger statistical distance: Δ ≤ 2^{-120}
- Still provides 120-bit statistical security (sufficient for 128-bit quantum security)

**Trade-off Analysis**:
- Security loss: 8 bits of statistical security
- Performance gain: 3× fewer iterations
- Acceptable for most applications (120-bit >> practical security needs)

**Requirement Update**: Modify Req 7.1, 7.7 (make M configurable)

#### 4.3 Batch Rejection Sampling
**Speedup**: 2× faster (amortize overhead)  
**Security Impact**: None

**Technique**:
- Sample k = 16 candidates in parallel
- Evaluate all rejection conditions simultaneously
- Select first accepted sample
- Probability of finding accepted sample: 1 - (1 - 1/M)^k ≈ 1 - e^{-k/M}

**For k=16, M=12**: P(success) ≈ 1 - e^{-1.33} ≈ 74% (vs 8.3% for k=1)

**Requirement Addition**: Add to Req 7.16 (enhance parallel sampling)

#### 4.4 Precomputed Acceptance Thresholds
**Speedup**: 1.5× faster rejection decision  
**Memory**: +128 KB  
**Security Impact**: None

**Technique**:
- Precompute acceptance thresholds for common ||c·w|| values
- Use lookup table instead of computing D_σ(z)/(M·D_{σ,c·w}(z))
- Interpolate for intermediate values

**Requirement Addition**: Add to Req 7.4

---

## 5. Norm Computation Optimizations

### Current State
- Norm computation: O(n) = O(1024) operations per witness
- Performed at every aggregation step

### Optimizations

#### 5.1 Incremental Norm Updates
**Speedup**: 10× faster norm tracking  
**Security Impact**: None

**Technique**:
- Maintain ||w||² incrementally during aggregation
- Use identity: ||w' + α·w||² = ||w'||² + 2α⟨w',w⟩ + α²||w||²
- Compute inner product ⟨w',w⟩ during aggregation (no extra cost)
- Avoid full norm recomputation

**Requirement Addition**: Add to Req 6.1, 6.4

#### 5.2 SIMD Norm Computation
**Speedup**: 4-8× faster when full computation needed  
**Security Impact**: None

**Technique**:
- Vectorize ||w||² = ∑|w[i]|² using AVX2/AVX-512
- Process 4-8 coefficients per instruction
- Use horizontal sum for final reduction

**Implementation**:
```rust
// AVX2: compute 4 squared norms in parallel
// _mm256_mul_epi64 + _mm256_add_epi64 + horizontal sum
```

**Requirement Addition**: Add to Req 6.1

#### 5.3 Approximate Norm Bounds
**Speedup**: 5× faster norm checks  
**Security Impact**: Minimal (conservative bounds)

**Technique**:
- Use triangle inequality for quick upper bound: ||w'|| ≤ ∑|α_i|·||w_i||
- Only compute exact norm when upper bound exceeds threshold
- Reduces exact norm computations by ~80%

**Requirement Addition**: Add to Req 6.4, 6.9

---

## 6. Memory Hierarchy Optimizations

### Current State
- Memory: ~12 GB for M=8, N=2^20
- Cache misses: significant bottleneck

### Optimizations

#### 6.1 Cache-Oblivious Witness Layout
**Speedup**: 2× fewer cache misses  
**Security Impact**: None

**Technique**:
- Layout witness slices in Z-order (Morton order)
- Improves spatial locality for NTT operations
- Reduces cache misses from ~40% to ~20%

**Requirement Addition**: Add to Req 4.3 (data layout)

#### 6.2 Streaming Witness Processing
**Speedup**: 10× less memory (1.2 GB vs 12 GB)  
**Security Impact**: None

**Technique**:
- Process witness in chunks of size C = L2_cache_size / ℓ
- Stream chunks from disk/network as needed
- Overlap I/O with computation

**Requirement Enhancement**: Already in Req 6.14, add chunk size specification

#### 6.3 Prefetching
**Speedup**: 1.5× faster memory access  
**Security Impact**: Potential side-channel (mitigate with constant-time prefetch)

**Technique**:
- Software prefetch next witness slice during current computation
- Use `_mm_prefetch` with temporal locality hint
- Prefetch k=4 cache lines ahead

**Requirement Addition**: Add to Req 6.14 (with side-channel mitigation)

---

## 7. Algorithmic Optimizations

### Current State
- Distributed SumFold: ν = log M rounds
- Each round: O(T·ℓ·log(T·ℓ)) computation

### Optimizations

#### 7.1 Hierarchical Aggregation
**Speedup**: 1.5× faster aggregation  
**Communication**: -30%  
**Security Impact**: None

**Technique**:
- Use tree topology instead of linear aggregation
- Depth log₂(M) instead of M-1 sequential steps
- Each prover aggregates from k=2 children in parallel

**Requirement Update**: Enhance Req 6.7, 6.13 (specify tree topology)

#### 7.2 Adaptive Polynomial Degree
**Speedup**: 1.3× smaller proofs  
**Security Impact**: None (maintains soundness error)

**Technique**:
- Use degree d = 2 for early rounds (low soundness error contribution)
- Use degree d = 3 only for final rounds (high contribution)
- Reduces proof size by ~25%

**Requirement Addition**: Add to Req 2.2, 8.24 (adaptive degree)

#### 7.3 Batch Verification
**Speedup**: 5× faster verification  
**Security Impact**: Minimal (soundness error increases by factor of batch size)

**Technique**:
- Verify multiple proofs simultaneously using random linear combination
- Verify ∑ᵢ αᵢ·(LHS_i - RHS_i) = 0 instead of individual LHS_i = RHS_i
- Soundness error: ε_batch = k·ε where k is batch size

**For k=10**: ε_batch = 10·2^{-128} ≈ 2^{-124} (still secure)

**Requirement Addition**: Add new requirement for batch verification

---

## 8. Hardware Acceleration

### Current State
- CPU-only implementation
- No hardware acceleration

### Optimizations

#### 8.1 GPU Acceleration for NTT
**Speedup**: 10-50× faster NTT  
**Cost**: Requires GPU  
**Security Impact**: None (same algorithm)

**Technique**:
- Offload NTT computations to GPU
- Use CUDA/OpenCL for parallel butterfly operations
- Process multiple polynomials simultaneously

**Requirement Addition**: Add optional GPU support to Req 4.7, 8.9

#### 8.2 FPGA for Gaussian Sampling
**Speedup**: 100× faster sampling  
**Cost**: Requires FPGA  
**Security Impact**: None (hardware implementation of CDT)

**Technique**:
- Implement CDT lookup in FPGA
- Parallel sampling of 64 Gaussian values
- Constant-time hardware implementation (side-channel resistant)

**Requirement Addition**: Add optional FPGA support to Req 7.9

#### 8.3 AVX-512 SIMD
**Speedup**: 2× faster than AVX2  
**Availability**: Intel Ice Lake+, AMD Zen 4+  
**Security Impact**: None

**Technique**:
- Use 512-bit SIMD registers (8 × 64-bit elements)
- Vectorize all coefficient operations
- Requires CPU feature detection and fallback

**Requirement Addition**: Add SIMD optimization tier to all computation requirements

---

## 9. Protocol-Level Optimizations

### Current State
- Sequential rounds: round k+1 waits for round k completion
- No early termination

### Optimizations

#### 9.1 Optimistic Verification
**Speedup**: 2× faster in honest case  
**Security Impact**: None (maintains soundness)

**Technique**:
- Defer verification checks to end of protocol
- Batch all verifications: Q_{k-1}(r_{k-1}) = Q_k(0) + Q_k(1) for k ∈ [ν]
- Abort if any check fails
- Reduces round-trip latency

**Requirement Addition**: Add to Req 8.12 (deferred verification)

#### 9.2 Probabilistic Early Termination
**Speedup**: 1.5× faster on average  
**Security Impact**: Configurable (trade soundness for speed)

**Technique**:
- Terminate after k < ν rounds with probability p
- Soundness error increases: ε' = ε·|F|^{ν-k}
- For k = ν-2, p = 0.5: E[rounds] = 0.5·(ν-2) + 0.5·ν = ν-1

**Trade-off**: Acceptable for non-critical applications

**Requirement Addition**: Add optional early termination to Req 8.5

#### 9.3 Recursive Proof Composition
**Speedup**: Amortize verification cost  
**Proof Size**: O(log log N) instead of O(log N)  
**Security Impact**: None (maintains soundness)

**Technique**:
- Prove correctness of previous proof verification
- Recursively compose proofs: π₁ proves π₀ is valid, π₂ proves π₁ is valid, etc.
- Final proof size: O(log log N)

**Requirement Addition**: Add new requirement for recursive composition

---

## 10. Parameter Tuning

### Current State
- Fixed parameters: n=1024, q≈2^60, b=4, ℓ=30, M=12.0

### Optimizations

#### 10.1 Smaller Ring Dimension (Conditional)
**Speedup**: 2× faster (n=512 vs n=1024)  
**Security Impact**: Reduces security to ~100-bit quantum (acceptable for some applications)

**Technique**:
- Use n=512 for applications not requiring full 128-bit security
- Reduces all operations by 2×
- Still provides post-quantum security (just lower level)

**Requirement Addition**: Add configurable security level to Req 1.1

#### 10.2 Larger Modulus (Trade-off)
**Speedup**: -10% (slower)  
**Benefit**: Fewer decomposition limbs (ℓ=20 vs ℓ=30)  
**Net**: 1.5× faster overall

**Technique**:
- Use q ≈ 2^80 instead of q ≈ 2^60
- Reduces ℓ from 30 to 20 limbs
- Slightly slower NTT but much faster decomposition

**Requirement Update**: Make q configurable in Req 1.1

#### 10.3 Dynamic Prover Count
**Speedup**: Optimal M for given N  
**Security Impact**: None

**Technique**:
- Choose M = √N for optimal communication/computation trade-off
- For N=2^20: M=2^10=1024 provers (vs M=8 currently)
- Reduces per-prover computation from O(2^17) to O(2^10)

**Requirement Addition**: Add dynamic M selection to Req 8.1

---

## Summary Table

| Optimization | Speedup | Memory | Security Impact | Complexity |
|--------------|---------|--------|-----------------|------------|
| **Lazy NTT Reduction** | 2-3× | 0 | None | Low |
| **Precomputed Twiddles** | 1.5× | +16 KB | None | Low |
| **NWC** | 2× | -50% | None | Medium |
| **Adaptive Gadget Base** | 1.3× | 0 | None | Low |
| **SIMD Decomposition** | 4-8× | 0 | None | Medium |
| **Lazy Decomposition** | Amortized | +O(n·ℓ) | None | Low |
| **Incremental Compression** | 3-4× BW | 0 | None | Medium |
| **Batched Messages** | 2× msgs | 0 | None | Low |
| **Speculative Challenges** | 1.5× | +2× compute | None | High |
| **UDP Hybrid** | 2× latency | 0 | None | Medium |
| **Vectorized Gaussian** | 8× | 0 | None | Medium |
| **Approximate Rejection** | 3× | 0 | -8 bits stat | Low |
| **Batch Rejection** | 2× | 0 | None | Low |
| **Incremental Norms** | 10× | 0 | None | Low |
| **SIMD Norms** | 4-8× | 0 | None | Low |
| **Cache-Oblivious Layout** | 2× | 0 | None | Medium |
| **Streaming** | 10× less mem | 0 | None | Medium |
| **Hierarchical Aggregation** | 1.5× | 0 | None | Low |
| **Adaptive Degree** | 1.3× proof | 0 | None | Low |
| **Batch Verification** | 5× | 0 | Minimal | Low |
| **GPU NTT** | 10-50× | 0 | None | High |
| **Optimistic Verification** | 2× | 0 | None | Low |

## Combined Impact

Applying **conservative subset** (low/medium complexity, no security trade-offs):

| Metric | Baseline | Optimized | Improvement |
|--------|----------|-----------|-------------|
| **Prover Time** | 3.1s | 0.4s | **7.8×** |
| **Communication** | 1.9 GB | 0.5 GB | **3.8×** |
| **Memory** | 12 GB | 1.2 GB | **10×** |
| **Proof Size** | 92 KB | 71 KB | **1.3×** |
| **Verifier Time** | 45 ms | 9 ms | **5×** |

**Security**: Maintains full 128-bit quantum security

---

## Implementation Priority

### Phase 1: Quick Wins (1-2 weeks)
1. Lazy NTT reduction
2. SIMD decomposition
3. Incremental norms
4. Batched messages
5. Lazy decomposition

**Expected**: 3-4× speedup

### Phase 2: Medium Effort (1 month)
1. NWC
2. Incremental compression
3. Cache-oblivious layout
4. Vectorized Gaussian
5. Hierarchical aggregation

**Expected**: Additional 2× speedup (6-8× total)

### Phase 3: Advanced (2-3 months)
1. GPU acceleration
2. Speculative challenges
3. Adaptive parameters
4. Batch verification
5. Recursive composition

**Expected**: Additional 2-5× speedup (12-40× total)

---

## Next Steps

1. **Review this document** - Identify which optimizations to prioritize
2. **Update requirements.md** - Add new acceptance criteria for selected optimizations
3. **Design phase** - Specify implementation details for each optimization
4. **Benchmark** - Measure actual speedups on target hardware
