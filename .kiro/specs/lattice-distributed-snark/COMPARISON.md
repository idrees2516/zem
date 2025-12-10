# Classical vs Lattice-Based Distributed SNARK Comparison

## Overview

This document compares the **classical (elliptic curve)** and **lattice-based (post-quantum)** implementations of the distributed SNARK system.

## Key Differences

### 1. Cryptographic Foundation

| Aspect | Classical (BN254) | Lattice-Based (Post-Quantum) |
|--------|-------------------|------------------------------|
| **Security Assumption** | Discrete Log, Pairing | Module-SIS, Module-LWE |
| **Quantum Security** | ❌ Broken by Shor's algorithm | ✅ Quantum-resistant |
| **Field** | F_p (254-bit prime) | Goldilocks (64-bit) or M61 (61-bit) |
| **Group** | Elliptic curve G1, G2 | Cyclotomic ring R_q = Z_q[X]/(X^n+1) |
| **Element Size** | 32 bytes (G1), 64 bytes (G2) | ~2KB (ring element, n=1024, q≈2^60) |

### 2. Polynomial Commitment Scheme

| Aspect | Classical (KZG/SamaritanPCS) | Lattice-Based (vSIS) |
|--------|------------------------------|----------------------|
| **Commitment** | C = g^{p(τ)} | C = A·w mod q |
| **Opening Proof** | π = g^{q(τ)} (1 group element) | π = (w, hint) (~10KB) |
| **Verification** | Pairing check e(C,h) = e(π,g) | Matrix-vector check + norm bound |
| **Proof Size** | O(1) = 48 bytes | O(λ) = ~10KB |
| **Prover Time** | O(n log n) with FFT | O(n log n) with NTT |
| **Verifier Time** | O(1) pairings (~5ms) | O(n) ring ops (~50ms) |

### 3. Performance Comparison

| Metric | Classical | Lattice-Based | Ratio |
|--------|-----------|---------------|-------|
| **Proof Size** | 8.5-9.9 KB | 85-99 KB | ~10× |
| **Prover Time** | 4.1-4.9× speedup (vs HyperPianist) | 3.5-4.2× speedup | ~0.85× |
| **Verifier Time** | 4.05-5.08 ms | 40-50 ms | ~10× |
| **Communication** | O(N) field elements (32 bytes each) | O(N·λ) ring elements (~2KB each) | ~60× |
| **Memory** | ~1GB for 2^20 gates | ~10GB for 2^20 gates | ~10× |

### 4. Complexity Guarantees

| Operation | Classical | Lattice-Based |
|-----------|-----------|---------------|
| **Prover P_i** | O(T) field ops | O(T·ℓ) ring ops (ℓ = decomposition limbs) |
| **Coordinator P₀** | O(T + M) | O(T·ℓ + M·λ) |
| **Communication** | O(N) field elements | O(N·ℓ) ring elements |
| **Proof Size** | O(log N) field + O(1) group | O(log N · λ) ring elements |
| **Verifier** | O(log N) field + O(M) MSM | O(log N · λ) ring + O(M·λ²) lattice ops |

### 5. Security Properties

| Property | Classical | Lattice-Based |
|----------|-----------|---------------|
| **Quantum Security** | ❌ No | ✅ Yes (128-bit quantum security) |
| **Soundness Error** | dμ/\|F\| ≈ 2^{-200} | dμ/\|F\| + 2^{-λ} ≈ 2^{-120} |
| **Knowledge Error** | negl(λ) | negl(λ) + lattice extraction error |
| **Completeness** | 1 (perfect) | 1 - 2^{-λ} (rejection sampling) |
| **Binding** | Discrete log | Module-SIS (worst-case lattice) |
| **Hiding** | Optional (randomness) | Statistical (LWE noise) |

### 6. Implementation Complexity

| Aspect | Classical | Lattice-Based |
|--------|-----------|---------------|
| **Dependencies** | arkworks (ark_ff, ark_ec, ark_bn254) | Custom lattice library + arkworks |
| **Lines of Code** | ~15,000 LOC | ~25,000 LOC (additional lattice ops) |
| **Testing Complexity** | Moderate | High (norm bounds, rejection sampling) |
| **Optimization** | Well-studied (Pippenger, MSM) | Active research (NTT, gadget decomp) |

## When to Use Each

### Use Classical (BN254) When:
- ✅ Quantum computers are not a threat in your timeframe
- ✅ Proof size and verification time are critical
- ✅ You need maximum performance today
- ✅ Compatibility with existing systems (Ethereum, etc.)

### Use Lattice-Based When:
- ✅ Post-quantum security is required
- ✅ Long-term security (10+ years)
- ✅ Regulatory requirements for quantum resistance
- ✅ Future-proofing your system
- ✅ Research/academic applications

## Migration Path

### Phase 1: Implement Both
- Maintain parallel implementations
- Share common components (sumcheck, folding logic)
- Allow runtime selection

### Phase 2: Hybrid Mode
- Use classical for speed-critical operations
- Use lattice for long-term storage/verification
- Gradual transition as quantum threat increases

### Phase 3: Pure Lattice
- Deprecate classical implementation
- Optimize lattice performance
- Full post-quantum security

## Technical Challenges

### Classical Challenges:
1. Quantum vulnerability (fundamental limitation)
2. Trusted setup for KZG (can use transparent alternatives)
3. Pairing-friendly curve requirements

### Lattice Challenges:
1. **Norm Growth**: Folding can cause ||w|| to grow exponentially
   - **Solution**: LatticeFold+ with gadget decomposition
2. **Proof Size**: Larger than classical (~10×)
   - **Solution**: RoK and Roll structured projections (Õ(λ) size)
3. **Rejection Sampling**: Prover may need to retry
   - **Solution**: Careful parameter selection (failure prob < 2^{-40})
4. **Implementation Complexity**: More moving parts
   - **Solution**: Modular design, extensive testing

## Conclusion

Both implementations serve different needs:
- **Classical**: Best performance today, but quantum-vulnerable
- **Lattice**: Future-proof, quantum-resistant, but larger proofs

The lattice-based version is essential for long-term security and represents the future of zero-knowledge proofs in a post-quantum world.
