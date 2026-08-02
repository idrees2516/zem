# Cyclo: Lightweight Lattice-based Folding via Partial Range Checks

This is a complete implementation of the Cyclo folding scheme from the paper:

> **Cyclo: Lightweight Lattice-based Folding via Partial Range Checks**  
> Albert Garreta, Helger Lipmaa, Urmas Luhaäär, and Michal Osadnik (2026)

## Overview

Cyclo is an efficient lattice-based folding scheme that improves upon LatticeFold+ with:

- **Amortized norm-refreshing**: No decomposition/range-check on accumulated witnesses
- **Extension commitment**: Vertical witness decomposition for efficiency
- **Pay-per-bit folding**: Efficient handling of R1CS/CCS over finite fields
- **Small proofs**: ~30 KB proof size (vs ~100 KB for LatticeFold+)
- **Bounded folding**: Supports 2^6 to 2^20 folding rounds

## Key Features

### 1. Amortized Norm-Refreshing Folding
Unlike previous schemes, Cyclo:
- Only checks norms on **input** witnesses (not accumulated ones)
- Achieves **additive** norm growth per round (not multiplicative)
- Can perform bounded number of folds before refreshing

### 2. Extension Commitment Protocol
- Decomposes witness "vertically" into single linear relation
- Base-2b decomposition with configurable base b
- Much more efficient than LatticeFold+'s double commitment

### 3. Range Test via Sum-Check
- Tests ||w||_∞ ≤ b using sum-check over extension field
- Single sum-check per input relation
- No batching needed due to amortized design

### 4. R1CS/CCS Reduction
- θ_k map: Low-norm, bit-size preserving F_q → R_q embedding
- Hybrid computation: Sum-check over F_q, commitment over R_q
- No witness decomposition needed when folding F_q constraints

## Architecture

```
cyclo/
├── mod.rs                    # Module exports
├── types.rs                  # Core types (ring elements, relations, etc.)
├── cyclotomic.rs             # Cyclotomic ring arithmetic
├── commitment.rs             # Ajtai commitment scheme
├── range_test.rs             # Range test protocol (Figure 1)
├── extension_commitment.rs   # Extension commitment (Figure 2)
├── folding.rs                # Main folding scheme (Figure 3)
├── r1cs_reduction.rs         # R1CS to linear relation (Section 7)
├── strong_sampling.rs        # Strong sampling sets (Appendix B)
├── parameters.rs             # Parameter selection (Section 6.1)
└── utils.rs                  # Utilities (transcript, polynomials)
```

## Usage

### Basic Example

```rust
use neo_lattice_zkvm::cyclo::*;
use neo_lattice_zkvm::field::GoldilocksField as F;

// 1. Setup parameters
let params = ParameterSet::<F>::default_128bit();

// 2. Create cyclotomic ring
let modulus = F::from_u64((1u64 << 50) - 1);
let ring = CyclotomicRing::new(params.conductor, modulus);

// 3. Setup commitment
let mut rng = rand::thread_rng();
let ajtai = AjtaiCommitment::new(
    ring.clone(),
    params.rank_a,
    params.witness_length,
    &mut rng,
);

// 4. Create folding scheme
let cyclo = CycloFolding::new(
    ring,
    params.to_cyclo_params(modulus),
    range_test,
    extension_commitment,
    folding_challenges,
);

// 5. Fold instances
let (new_acc, new_witness, proof) = cyclo.prove(
    &accumulator,
    &acc_witness,
    &inputs,
    &matrices,
    &ajtai.matrix_a,
    &mut transcript,
)?;
```

### Running the Demo

```bash
cargo run --example cyclo_folding_demo
```

## Core Components

### 1. Cyclotomic Rings

```rust
pub struct CyclotomicRing<F: FiniteField> {
    pub conductor: usize,  // f
    pub degree: usize,     // φ = φ(f)
    pub modulus: F,        // q
}

pub struct RingElement<F: FiniteField> {
    pub coeffs: Vec<F>,    // Coefficients in powerful basis
    pub conductor: usize,
    pub degree: usize,
}
```

### 2. Principal Linear Relation

The accumulator relation:
```
Ξ^lin_{A,(M_i),a,n,m,B}: 
  - A ∈ R_q^{a×m}: Ajtai commitment matrix
  - (M_i): Constraint matrices
  - (r_i): Challenge points
  - (b_i): Evaluation points
  - y: Image vector
  - w: Witness with ||w||_∞ ≤ B
```

### 3. θ_k Map

Low-norm embedding F_q → R_q:
```rust
pub struct ThetaMap<F: FiniteField> {
    pub base_k: usize,
    pub ring: CyclotomicRing<F>,
}

// For c ∈ F_q, encode as p_c(X) = Σ c_i X^i
// where c = Σ c_i k^i (base-k decomposition)
let ring_elem = theta_map.preimage(field_elem);
```

### 4. Folding Workflow

```
Input Relations        Extension         Range Test
  Ξ_0^lin           Commitment          
     ↓           ────────────→      ────────────→
  Extended                          Range-Checked
  Ξ_0'^lin                          Ξ_0''^lin
                                         ↓
Accumulator                         Unification
  Ξ_acc^lin      ←────────────    (Sum-Check)
     ↓                                   ↓
   Fold                            Fold with
(Challenge s)   ←────────────    Shared Point
     ↓
New Accumulator
  Ξ_acc'^lin
```

## Parameter Sets

### Default (128-bit security)
```rust
conductor: 256         // f = 2^8
degree: 128            // φ
modulus_bits: 50       // ~2^50
base_b: 1              // Ternary
norm_bound_B: 1024     // 2^10
rank_a: 13
witness_length: 2^20
max_rounds: 64
```

**Estimated Performance:**
- Proof size: ~31.8 KB
- Extension commitment: ~36.7s
- Memory: ~1.56 GB (witness storage)

### High Security (256-bit)
```rust
conductor: 512
degree: 256
modulus_bits: 60
rank_a: 26
```

**Estimated Performance:**
- Proof size: ~40.4 KB
- Higher security margin

## Comparison with LatticeFold+

| Metric | LatticeFold+ | Cyclo | Improvement |
|--------|--------------|-------|-------------|
| Proof Size | ~100 KB | ~31.8 KB | **3.1x smaller** |
| Witness Decomposition | Yes (log B chunks) | Only for input | **Simplified** |
| Accumulator Check | Yes (double commit) | No | **3.5x faster** |
| Norm Growth | Multiplicative | Additive | **Better bounds** |
| Folding Rounds | Unlimited | Bounded (2^6-2^20) | Practical limit |

## Implementation Details

### Strong Sampling Sets

Two approaches:

1. **Exact (Lyubashevsky-Seiler):**
   - Based on cyclotomic splitting
   - Guarantees all differences invertible
   - Requires special modulus

2. **Approximate (Biased Ternary):**
   - Uniform over {-1, 0, 1}
   - κ_nu ≈ k/q^{φ/k} non-unit probability
   - NTT-friendly parameters

### Sum-Check Optimization

- Degree-2 for R1CS reduction (Q_0·Q_1 - Q_2)
- Degree-(2b+2) for range test
- Batching with multilinear eq polynomials
- Extension field F_{q^e} for soundness amplification

### Norm Management

Accumulated norm after T rounds:
```
β_T = β_0 + T · L · b · γ
```

Where:
- β_0: Initial norm bound
- L: Relations per round
- b: Decomposition base
- γ: Challenge expansion factor (~2 for ternary)

## Security Considerations

### Knowledge Soundness

Total knowledge error:
```
κ ≤ L/|D| + (ℓ_0 + ℓ_1)/q^e + Lℓ_1(2b+2)/q^e + Lℓ_C/|C| + Lκ_nu
```

Components:
- Folding challenge sampling
- Unification sum-check
- Range test sum-check  
- Extension commitment
- Non-unit probability

### SIS Hardness

Parameters selected for:
- Root Hermite factor δ_0 = 1.0045
- 128-bit quantum security
- Using LatticeEstimator

## Advanced Features

### IVC Construction

```rust
let mut accumulator = empty_accumulator();

for step in computation_steps {
    let instance = compute_step_instance(step);
    
    (accumulator, witness, proof) = cyclo.prove(
        &accumulator,
        &witness,
        &[instance],
        &matrices,
        &commitment_key,
        &mut transcript,
    )?;
}
```

### Norm Refreshing

Combine with LatticeFold+ every k rounds:
```rust
if rounds % refresh_interval == 0 {
    // Use LatticeFold+ to refresh norm
    accumulator = latticefold_plus.refresh(accumulator)?;
}
```

### Parallel Folding

Fold multiple relations simultaneously:
```rust
let inputs = vec![instance1, instance2, instance3];
let (acc, wit, proof) = cyclo.prove(
    &accumulator,
    &witness,
    &inputs,  // Fold all at once
    &matrices,
    &key,
    &mut transcript,
)?;
```

## Limitations

1. **Bounded Rounds**: Maximum folding depth (configurable 2^6 to 2^20)
2. **Memory Usage**: Stores (L+1)·m·log(2B) ring elements (~1-2 GB)
3. **NTT Requirements**: Optimal with NTT-friendly modulus
4. **Extension Degree**: Small e=2 for efficiency, may need larger for security

## Future Optimizations

- [ ] Full NTT implementation for fast polynomial multiplication
- [ ] AVX-512 IFMA52 optimizations (like Intel HEXL)
- [ ] Parallel sum-check execution
- [ ] Streaming witness processing
- [ ] Hardware acceleration support
- [ ] Recursive verification circuit
- [ ] PCD construction (merging accumulators)

## References

- **Cyclo Paper**: Garreta et al., 2026
- **LatticeFold+**: Boneh & Chen, CRYPTO 2025
- **Neo**: Nguyen & Setty, 2025
- **Lyubashevsky-Seiler**: Short Invertible Elements, EUROCRYPT 2018

## License

This implementation follows the same license as the neo-lattice-zkvm project.

## Citation

```bibtex
@inproceedings{cyclo2026,
  author = {Garreta, Albert and Lipmaa, Helger and Luha{\"a}{\"a}r, Urmas and Osadnik, Michal},
  title = {Cyclo: Lightweight Lattice-based Folding via Partial Range Checks},
  year = {2026}
}
```
