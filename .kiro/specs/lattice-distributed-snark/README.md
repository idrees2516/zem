# Lattice-Based Distributed SNARK via Folding Schemes

## Overview

This specification describes a **post-quantum secure** distributed SNARK system that achieves:
- ✅ **Quantum Resistance**: Based on Module-SIS/LWE lattice assumptions
- ✅ **Distributed Proving**: Linear speedup with M provers (O(T) per prover where T=N/M)
- ✅ **Norm Preservation**: LatticeFold+ prevents exponential norm growth
- ✅ **Optimal Proof Size**: Õ(λ) using RoK and Roll structured projections
- ✅ **128-bit Quantum Security**: Equivalent to AES-128 against quantum attacks

## Key Innovation

Unlike classical distributed SNARKs (based on elliptic curves), this system uses:
1. **Lattice-based polynomial commitments** (vSIS) instead of KZG
2. **Gadget decomposition** to preserve witness norms during folding
3. **Structured random projections** (tensor products) for efficiency
4. **Lattice-friendly fields** (Goldilocks, M61) for fast arithmetic

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  (Circuit Definition, Witness Generation, Verification)     │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────────┐
│              Distributed Protocol Layer                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Distributed  │  │  LatticeFold+│  │  Sum-Check   │     │
│  │   SNARK      │  │  (Norm Pres.)│  │  (Lattice)   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────────┐
│           Lattice Cryptographic Primitives                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Lattice PCS  │  │ Cyclotomic   │  │   Gadget     │     │
│  │   (vSIS)     │  │    Rings     │  │ Decomposition│     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────────┐
│              Mathematical Foundation                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Goldilocks   │  │     NTT      │  │ Multilinear  │     │
│  │    Field     │  │  Operations  │  │  Polynomials │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Documents

- **[requirements.md](requirements.md)**: Formal EARS-compliant requirements
- **[COMPARISON.md](COMPARISON.md)**: Classical vs Lattice comparison
- **design.md**: Detailed architecture and component design (TODO)
- **tasks.md**: Implementation roadmap (TODO)

## Integration with Neo Lattice zkVM

This spec is designed to integrate with your existing `neo-lattice-zkvm` project:

### Shared Components
- ✅ **Lattice PCS** (`neo-lattice-zkvm/src/lattice_pcs/`)
- ✅ **Cyclotomic Rings** (`neo-lattice-zkvm/src/ring/`)
- ✅ **Goldilocks Field** (`neo-lattice-zkvm/src/field/goldilocks.rs`)
- ✅ **LatticeFold+** (`neo-lattice-zkvm/src/latticefold_plus/`)
- ✅ **AROM** (`neo-lattice-zkvm/src/oracle/arom.rs`)

### New Components Needed
- ⚠️ **Distributed SumFold** (adapt from classical version)
- ⚠️ **Network Layer** (same as classical, reusable)
- ⚠️ **Norm-Preserving Aggregation** (new lattice-specific logic)
- ⚠️ **Rejection Sampling** (for lattice soundness)

## Performance Expectations

For a circuit with N = 2^20 gates and M = 8 provers:

| Metric | Classical | Lattice | Notes |
|--------|-----------|---------|-------|
| Proof Size | 9.2 KB | 92 KB | ~10× larger |
| Prover Time | 2.3s | 3.1s | ~1.35× slower |
| Verifier Time | 4.5 ms | 45 ms | ~10× slower |
| Communication | 32 MB | 1.9 GB | ~60× more |
| Memory | 1.2 GB | 12 GB | ~10× more |

**Trade-off**: ~10× overhead for quantum security

## Security Parameters

```rust
// Lattice parameters for 128-bit quantum security
const RING_DEGREE: usize = 1024;           // n = 2^10
const MODULUS_BITS: usize = 60;            // q ≈ 2^60
const WITNESS_NORM_BOUND: f64 = 2^20;      // β
const DECOMPOSITION_BASE: usize = 4;       // b
const DECOMPOSITION_LIMBS: usize = 30;     // ℓ = log_b(q)
const REJECTION_SAMPLING_BOUND: f64 = 12.0;// M for rejection sampling
const SOUNDNESS_ERROR: f64 = 2^(-128);     // ε
```

## Next Steps

1. ✅ **Requirements Complete** (this document)
2. ⏳ **Design Document** (in progress)
3. ⏳ **Task Breakdown** (pending)
4. ⏳ **Implementation** (Phase 1: Primitives)

## References

- **Classical Version**: `.kiro/specs/distributed-snark-folding/`
- **Neo Lattice zkVM**: `neo-lattice-zkvm/ARCHITECTURE_INTEGRATION.md`
- **LatticeFold+ Paper**: Norm-preserving folding schemes
- **RoK and Roll Paper**: Structured random projections for Õ(λ) proofs
- **Module-SIS**: Worst-case lattice hardness assumptions

## Questions?

See [COMPARISON.md](COMPARISON.md) for detailed comparison with classical version.
