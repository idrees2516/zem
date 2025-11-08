# Neo: Lattice-based Folding Scheme - Design Document

## Overview

This document provides a comprehensive design for implementing Neo, a lattice-based folding scheme for CCS (Customizable Constraint System) that operates over small prime fields with pay-per-bit commitment costs. Neo provides plausible post-quantum security while maintaining efficiency comparable to elliptic curve-based folding schemes like HyperNova.

### Key Innovations

1. **Pay-per-bit Ajtai Commitments**: Commitment costs scale linearly with bit-width of values
2. **Small Field Support**: Native support for Goldilocks (2^64 - 2^32 + 1) and M61 (2^61 - 1) fields
3. **Efficient Folding**: Single sum-check invocation over extension fields instead of cyclotomic rings
4. **Post-Quantum Security**: Based on Module-SIS hardness assumption

### Architecture Principles

- **Modular Design**: Separate concerns into distinct layers (field arithmetic, ring operations, commitments, folding)
- **Type Safety**: Strong typing for field elements, ring elements, polynomials, and commitments
- **Performance**: Optimize for NTT-based polynomial multiplication and SIMD operations
- **Extensibility**: Support multiple field choices and parameter sets

## Architecture

### System Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│              (IVC/PCD, SNARK Compression)                    │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    Folding Scheme Layer                      │
│         (CCS Folding, RLC, Decomposition, Sum-Check)        │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                  Commitment Scheme Layer                     │
│        (Ajtai Commitments, Matrix Commitments)              │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                 Polynomial & Ring Layer                      │
│    (Multilinear Extensions, Cyclotomic Rings, NTT)          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    Field Arithmetic Layer                    │
│         (Goldilocks, M61, Extension Fields)                 │
└─────────────────────────────────────────────────────────────┘
```


## Components and Interfaces

### 1. Field Arithmetic Layer

#### 1.1 Base Field Interface

```rust
trait Field: Clone + Copy + Debug {
    const MODULUS: u64;
    const MODULUS_BITS: usize;
    const TWO_ADICITY: usize;
    
    fn zero() -> Self;
    fn one() -> Self;
    fn from_u64(val: u64) -> Self;
    fn to_canonical_u64(&self) -> u64;
    
    fn add(&self, rhs: &Self) -> Self;
    fn sub(&self, rhs: &Self) -> Self;
    fn mul(&self, rhs: &Self) -> Self;
    fn neg(&self) -> Self;
    fn inv(&self) -> Option<Self>;
    
    fn pow(&self, exp: u64) -> Self;
    fn sqrt(&self) -> Option<Self>;
    
    // Batch operations for SIMD
    fn batch_add(a: &[Self], b: &[Self]) -> Vec<Self>;
    fn batch_mul(a: &[Self], b: &[Self]) -> Vec<Self>;
}
```

#### 1.2 Goldilocks Field Implementation

The Goldilocks field uses modulus q = 2^64 - 2^32 + 1.

**Key Properties**:
- 64-bit prime allowing efficient arithmetic
- q ≡ 1 + 2^2 (mod 4·2^2), so e = 2
- Supports NTT with d = 64 (cyclotomic ring degree)
- Extension degree τ = d/e = 32

**Arithmetic Implementation**:

```rust
struct GoldilocksField {
    value: u64,  // Always in range [0, MODULUS)
}

impl GoldilocksField {
    const MODULUS: u64 = (1u64 << 64) - (1u64 << 32) + 1;
    const EPSILON: u64 = (1u64 << 32) - 1;
    
    // Fast reduction using q = 2^64 - ε where ε = 2^32 - 1
    fn reduce128(x: u128) -> u64 {
        let (lo, hi) = (x as u64, (x >> 64) as u64);
        // x mod q = lo + hi·ε (mod q)
        let sum = lo as u128 + (hi as u128) * (Self::EPSILON as u128);
        let (sum_lo, sum_hi) = (sum as u64, (sum >> 64) as u64);
        let result = sum_lo.wrapping_add(sum_hi.wrapping_mul(Self::EPSILON));
        
        // Final conditional subtraction
        if result >= Self::MODULUS {
            result - Self::MODULUS
        } else {
            result
        }
    }
    
    fn add_impl(a: u64, b: u64) -> u64 {
        let sum = a as u128 + b as u128;
        Self::reduce128(sum)
    }
    
    fn mul_impl(a: u64, b: u64) -> u64 {
        let prod = (a as u128) * (b as u128);
        Self::reduce128(prod)
    }
}
```


#### 1.3 Mersenne 61 Field Implementation

The M61 field uses modulus q = 2^61 - 1.

**Key Properties**:
- Mersenne prime enabling very fast modular reduction
- q ≡ 1 (mod 128), so e = 1 and ring splits completely
- Extension degree τ = 64
- Requires F_q^2 extension for 128-bit security in sum-check

**Arithmetic Implementation**:

```rust
struct M61Field {
    value: u64,  // Always in range [0, 2^61 - 1)
}

impl M61Field {
    const MODULUS: u64 = (1u64 << 61) - 1;
    const MODULUS_BITS: usize = 61;
    
    // Ultra-fast reduction for Mersenne prime
    fn reduce(x: u64) -> u64 {
        // For x < 2^122, we need at most 2 reductions
        let reduced = (x & Self::MODULUS) + (x >> 61);
        if reduced >= Self::MODULUS {
            reduced - Self::MODULUS
        } else {
            reduced
        }
    }
    
    fn reduce128(x: u128) -> u64 {
        // Split into 61-bit chunks
        let lo = (x & ((1u128 << 61) - 1)) as u64;
        let mid = ((x >> 61) & ((1u128 << 61) - 1)) as u64;
        let hi = (x >> 122) as u64;
        
        // Reduce: x = lo + mid·2^61 + hi·2^122
        //           = lo + mid·2^61 + hi·2^61 (mod 2^61-1)
        //           = lo + (mid + hi)·2^61 (mod 2^61-1)
        //           = lo + (mid + hi) (mod 2^61-1)
        let sum = lo + mid + hi;
        Self::reduce(sum)
    }
    
    fn mul_impl(a: u64, b: u64) -> u64 {
        let prod = (a as u128) * (b as u128);
        Self::reduce128(prod)
    }
}
```

#### 1.4 Extension Field Implementation

Extension fields F_q^k are implemented as F_q[X]/(f(X)) where f(X) is irreducible.

```rust
struct ExtensionField<F: Field, const K: usize> {
    coeffs: [F; K],  // Coefficients of polynomial representation
}

impl<F: Field, const K: usize> ExtensionField<F, K> {
    // For F_q^2, use f(X) = X^2 + 1 (irreducible when q ≡ 3 mod 4)
    // For Goldilocks: X^2 + 7 is irreducible
    
    fn mul_extension2(a: &[F; 2], b: &[F; 2]) -> [F; 2] {
        // (a0 + a1·X)(b0 + b1·X) = (a0·b0 - a1·b1) + (a0·b1 + a1·b0)·X
        // where X^2 = -1 (or -7 for Goldilocks)
        let a0b0 = a[0].mul(&b[0]);
        let a1b1 = a[1].mul(&b[1]);
        let a0b1 = a[0].mul(&b[1]);
        let a1b0 = a[1].mul(&b[0]);
        
        [
            a0b0.sub(&a1b1.mul(&Self::NON_RESIDUE)),
            a0b1.add(&a1b0)
        ]
    }
}
```


### 2. Polynomial & Ring Layer

#### 2.1 Cyclotomic Ring Structure

```rust
struct CyclotomicRing<F: Field> {
    degree: usize,           // d = degree of Φ_η
    modulus_poly: Vec<F>,    // Coefficients of Φ_η
    ntt_enabled: bool,       // Whether NTT is available
    root_of_unity: Option<F>, // Primitive d-th root of unity (if exists)
}

struct RingElement<F: Field> {
    coeffs: Vec<F>,  // Polynomial coefficients, length = degree
}

impl<F: Field> CyclotomicRing<F> {
    // Create ring R_q = F_q[X]/(X^d + 1) for power-of-2 d
    fn new_power_of_two(degree: usize) -> Self {
        assert!(degree.is_power_of_two());
        
        // Check if NTT is available: need primitive 2d-th root of unity
        let ntt_enabled = Self::check_ntt_availability(degree);
        let root_of_unity = if ntt_enabled {
            Some(Self::find_primitive_root(2 * degree))
        } else {
            None
        };
        
        Self {
            degree,
            modulus_poly: vec![F::one()], // X^d + 1
            ntt_enabled,
            root_of_unity,
        }
    }
    
    // Polynomial multiplication in R_q
    fn mul(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        if self.ntt_enabled {
            self.mul_ntt(a, b)
        } else {
            self.mul_schoolbook(a, b)
        }
    }
    
    // NTT-based multiplication (O(d log d))
    fn mul_ntt(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        let omega = self.root_of_unity.unwrap();
        
        // Forward NTT
        let a_ntt = self.ntt_forward(&a.coeffs, omega);
        let b_ntt = self.ntt_forward(&b.coeffs, omega);
        
        // Pointwise multiplication
        let c_ntt: Vec<F> = a_ntt.iter()
            .zip(b_ntt.iter())
            .map(|(x, y)| x.mul(y))
            .collect();
        
        // Inverse NTT
        let c_coeffs = self.ntt_inverse(&c_ntt, omega);
        
        RingElement { coeffs: c_coeffs }
    }
    
    // Cooley-Tukey NTT (radix-2 decimation-in-time)
    fn ntt_forward(&self, coeffs: &[F], omega: F) -> Vec<F> {
        let n = coeffs.len();
        assert!(n.is_power_of_two());
        
        let mut result = coeffs.to_vec();
        let mut m = n;
        let mut k = 1;
        
        while m > 1 {
            m /= 2;
            let omega_m = omega.pow((n / (2 * m)) as u64);
            
            for i in 0..k {
                let mut omega_j = F::one();
                for j in 0..m {
                    let t = omega_j.mul(&result[i * 2 * m + j + m]);
                    let u = result[i * 2 * m + j];
                    result[i * 2 * m + j] = u.add(&t);
                    result[i * 2 * m + j + m] = u.sub(&t);
                    omega_j = omega_j.mul(&omega_m);
                }
            }
            k *= 2;
        }
        
        result
    }
    
    // Gentleman-Sande inverse NTT
    fn ntt_inverse(&self, coeffs: &[F], omega: F) -> Vec<F> {
        let n = coeffs.len();
        let omega_inv = omega.inv().unwrap();
        let n_inv = F::from_u64(n as u64).inv().unwrap();
        
        let mut result = self.ntt_forward(coeffs, omega_inv);
        
        // Scale by 1/n
        for coeff in &mut result {
            *coeff = coeff.mul(&n_inv);
        }
        
        result
    }
}
```


#### 2.2 Coefficient Embedding and Extraction

```rust
impl<F: Field> RingElement<F> {
    // Coefficient embedding: R_q → F_q^d
    fn to_coefficient_vector(&self) -> Vec<F> {
        self.coeffs.clone()
    }
    
    // Inverse: F_q^d → R_q
    fn from_coefficient_vector(coeffs: Vec<F>) -> Self {
        RingElement { coeffs }
    }
    
    // Constant term extraction: R_q → F_q
    fn constant_term(&self) -> F {
        self.coeffs[0]
    }
    
    // Infinity norm of ring element
    fn norm_infinity(&self) -> u64 {
        self.coeffs.iter()
            .map(|c| {
                let val = c.to_canonical_u64();
                let modulus = F::MODULUS;
                // Balanced representation: map to [-q/2, q/2]
                if val <= modulus / 2 {
                    val
                } else {
                    modulus - val
                }
            })
            .max()
            .unwrap_or(0)
    }
}
```

#### 2.3 Rotation Matrices

For efficient matrix-vector operations with ring elements:

```rust
struct RotationMatrix<F: Field> {
    ring: CyclotomicRing<F>,
    element: RingElement<F>,
    matrix: Vec<Vec<F>>,  // d×d matrix representation
}

impl<F: Field> RotationMatrix<F> {
    // Construct rotation matrix for ring element a
    // rot(a) · cf(b) = cf(a·b)
    fn new(ring: &CyclotomicRing<F>, element: &RingElement<F>) -> Self {
        let d = ring.degree;
        let mut matrix = vec![vec![F::zero(); d]; d];
        
        // For X^d + 1, rotation matrix has special structure
        // Column i is X^i · a reduced modulo X^d + 1
        let mut current = element.clone();
        matrix[0] = current.coeffs.clone();
        
        for i in 1..d {
            // Multiply by X: shift coefficients and negate last one
            let mut next_coeffs = vec![F::zero(); d];
            next_coeffs[0] = current.coeffs[d-1].neg();
            for j in 1..d {
                next_coeffs[j] = current.coeffs[j-1];
            }
            current = RingElement { coeffs: next_coeffs };
            matrix[i] = current.coeffs.clone();
        }
        
        // Transpose to get column-major form
        let matrix_t = Self::transpose(&matrix);
        
        Self {
            ring: ring.clone(),
            element: element.clone(),
            matrix: matrix_t,
        }
    }
    
    // Matrix-vector multiplication
    fn mul_vector(&self, vec: &[F]) -> Vec<F> {
        assert_eq!(vec.len(), self.matrix.len());
        
        self.matrix.iter()
            .map(|row| {
                row.iter()
                    .zip(vec.iter())
                    .map(|(a, b)| a.mul(b))
                    .fold(F::zero(), |acc, x| acc.add(&x))
            })
            .collect()
    }
    
    fn transpose(matrix: &[Vec<F>]) -> Vec<Vec<F>> {
        let rows = matrix.len();
        let cols = matrix[0].len();
        let mut result = vec![vec![F::zero(); rows]; cols];
        
        for i in 0..rows {
            for j in 0..cols {
                result[j][i] = matrix[i][j];
            }
        }
        
        result
    }
}
```


#### 2.4 Multilinear Polynomials

```rust
struct MultilinearPolynomial<F: Field> {
    evaluations: Vec<F>,  // Evaluations over Boolean hypercube
    num_vars: usize,      // Number of variables (log2 of evaluations.len())
}

impl<F: Field> MultilinearPolynomial<F> {
    fn new(evaluations: Vec<F>) -> Self {
        let len = evaluations.len();
        assert!(len.is_power_of_two(), "Length must be power of 2");
        let num_vars = len.trailing_zeros() as usize;
        
        Self { evaluations, num_vars }
    }
    
    // Evaluate multilinear extension at point r ∈ F^ℓ
    fn evaluate(&self, point: &[F]) -> F {
        assert_eq!(point.len(), self.num_vars);
        
        // Use recursive formula: MLE(r) = Σ_{x∈{0,1}^ℓ} eval[x] · eq(x, r)
        // Optimized using dynamic programming
        let mut current = self.evaluations.clone();
        
        for r_i in point.iter() {
            let half = current.len() / 2;
            let mut next = Vec::with_capacity(half);
            
            for j in 0..half {
                // Interpolate: (1 - r_i) · current[j] + r_i · current[j + half]
                let left = current[j].mul(&F::one().sub(r_i));
                let right = current[j + half].mul(r_i);
                next.push(left.add(&right));
            }
            
            current = next;
        }
        
        assert_eq!(current.len(), 1);
        current[0]
    }
    
    // Compute equality polynomial: eq(x, r) = ∏ᵢ (xᵢ·rᵢ + (1-xᵢ)·(1-rᵢ))
    fn eq_poly(x: &[bool], r: &[F]) -> F {
        assert_eq!(x.len(), r.len());
        
        x.iter().zip(r.iter())
            .map(|(xi, ri)| {
                if *xi {
                    *ri
                } else {
                    F::one().sub(ri)
                }
            })
            .fold(F::one(), |acc, val| acc.mul(&val))
    }
    
    // Partial evaluation: fix first k variables
    fn partial_eval(&self, values: &[F]) -> Self {
        let k = values.len();
        assert!(k <= self.num_vars);
        
        let mut current = self.evaluations.clone();
        
        for val in values {
            let half = current.len() / 2;
            let mut next = Vec::with_capacity(half);
            
            for j in 0..half {
                let interpolated = current[j].mul(&F::one().sub(val))
                    .add(&current[j + half].mul(val));
                next.push(interpolated);
            }
            
            current = next;
        }
        
        Self {
            evaluations: current,
            num_vars: self.num_vars - k,
        }
    }
}
```


### 3. Commitment Scheme Layer

#### 3.1 Ajtai Commitment Core

```rust
struct AjtaiCommitmentScheme<F: Field> {
    ring: CyclotomicRing<F>,
    kappa: usize,              // Commitment dimension (rows)
    m: usize,                  // Message dimension (columns)
    public_matrix: Vec<Vec<RingElement<F>>>,  // κ×m matrix over R_q
    norm_bound: u64,           // Maximum allowed witness norm
}

impl<F: Field> AjtaiCommitmentScheme<F> {
    // Setup: Generate random matrix A ∈ R_q^{κ×m}
    fn setup(ring: CyclotomicRing<F>, kappa: usize, m: usize, norm_bound: u64) -> Self {
        let mut rng = thread_rng();
        let mut public_matrix = Vec::with_capacity(kappa);
        
        for _ in 0..kappa {
            let mut row = Vec::with_capacity(m);
            for _ in 0..m {
                // Sample uniformly random ring element
                let coeffs: Vec<F> = (0..ring.degree)
                    .map(|_| F::from_u64(rng.gen::<u64>() % F::MODULUS))
                    .collect();
                row.push(RingElement { coeffs });
            }
            public_matrix.push(row);
        }
        
        Self {
            ring,
            kappa,
            m,
            public_matrix,
            norm_bound,
        }
    }
    
    // Commit to vector z ∈ R_q^m with ||z||_∞ ≤ norm_bound
    fn commit(&self, witness: &[RingElement<F>]) -> Result<Commitment<F>, Error> {
        assert_eq!(witness.len(), self.m);
        
        // Check norm bound
        for w in witness {
            if w.norm_infinity() > self.norm_bound {
                return Err(Error::NormBoundViolation);
            }
        }
        
        // Compute c = A·z ∈ R_q^κ
        let mut commitment = Vec::with_capacity(self.kappa);
        
        for row in &self.public_matrix {
            let mut sum = RingElement {
                coeffs: vec![F::zero(); self.ring.degree]
            };
            
            for (a_ij, z_j) in row.iter().zip(witness.iter()) {
                let prod = self.ring.mul(a_ij, z_j);
                sum = self.ring.add(&sum, &prod);
            }
            
            commitment.push(sum);
        }
        
        Ok(Commitment {
            values: commitment,
            scheme: self.clone(),
        })
    }
    
    // Verify opening: check that Com(witness) = commitment
    fn verify_opening(&self, commitment: &Commitment<F>, witness: &[RingElement<F>]) 
        -> Result<bool, Error> {
        let recomputed = self.commit(witness)?;
        Ok(commitment.values == recomputed.values)
    }
}

struct Commitment<F: Field> {
    values: Vec<RingElement<F>>,  // κ ring elements
    scheme: AjtaiCommitmentScheme<F>,
}

impl<F: Field> Commitment<F> {
    // Linear homomorphism: α·C₁ + β·C₂
    fn linear_combination(
        commitments: &[Self],
        scalars: &[RingElement<F>],
    ) -> Self {
        assert_eq!(commitments.len(), scalars.len());
        assert!(!commitments.is_empty());
        
        let kappa = commitments[0].values.len();
        let ring = &commitments[0].scheme.ring;
        
        let mut result = vec![
            RingElement { coeffs: vec![F::zero(); ring.degree] };
            kappa
        ];
        
        for (commitment, scalar) in commitments.iter().zip(scalars.iter()) {
            for (i, c_i) in commitment.values.iter().enumerate() {
                let scaled = ring.mul(scalar, c_i);
                result[i] = ring.add(&result[i], &scaled);
            }
        }
        
        Commitment {
            values: result,
            scheme: commitments[0].scheme.clone(),
        }
    }
}
```


#### 3.2 Pay-Per-Bit Matrix Commitment

The key innovation: map field vectors to ring vectors via coefficient packing.

```rust
struct MatrixCommitmentScheme<F: Field> {
    ajtai: AjtaiCommitmentScheme<F>,
    packing_degree: usize,  // d = ring degree
}

impl<F: Field> MatrixCommitmentScheme<F> {
    fn new(ring: CyclotomicRing<F>, kappa: usize, norm_bound: u64) -> Self {
        let packing_degree = ring.degree;
        // Message dimension m is determined by vector length / packing_degree
        
        Self {
            ajtai: AjtaiCommitmentScheme::setup(ring, kappa, 0, norm_bound),
            packing_degree,
        }
    }
    
    // Commit to field vector f ∈ F_q^N with pay-per-bit costs
    fn commit_vector(&mut self, vector: &[F], bit_widths: &[usize]) 
        -> Result<VectorCommitment<F>, Error> {
        assert_eq!(vector.len(), bit_widths.len());
        
        // Pack field elements into ring elements
        let ring_vector = self.pack_to_ring(vector, bit_widths)?;
        
        // Update Ajtai scheme dimension if needed
        if self.ajtai.m != ring_vector.len() {
            self.ajtai.m = ring_vector.len();
        }
        
        // Commit using Ajtai scheme
        let commitment = self.ajtai.commit(&ring_vector)?;
        
        Ok(VectorCommitment {
            commitment,
            original_length: vector.len(),
            bit_widths: bit_widths.to_vec(),
        })
    }
    
    // Pack field vector into ring vector with coefficient embedding
    // Key insight: d consecutive field elements → 1 ring element
    fn pack_to_ring(&self, vector: &[F], bit_widths: &[usize]) 
        -> Result<Vec<RingElement<F>>, Error> {
        let d = self.packing_degree;
        let n = vector.len();
        
        // Pad to multiple of d
        let padded_len = ((n + d - 1) / d) * d;
        let mut padded = vector.to_vec();
        padded.resize(padded_len, F::zero());
        
        let mut ring_elements = Vec::new();
        
        // Pack each chunk of d field elements
        for chunk_idx in 0..(padded_len / d) {
            let start = chunk_idx * d;
            let end = start + d;
            let chunk = &padded[start..end];
            
            // Create ring element: w_i = Σⱼ f_{i·d+j} · X^j
            let ring_elem = RingElement {
                coeffs: chunk.to_vec()
            };
            
            // Verify norm bound based on bit-widths
            let max_bit_width = bit_widths[start..end.min(n)]
                .iter()
                .max()
                .copied()
                .unwrap_or(0);
            
            let max_value = if max_bit_width < 64 {
                (1u64 << max_bit_width) - 1
            } else {
                u64::MAX
            };
            
            if ring_elem.norm_infinity() > max_value {
                return Err(Error::BitWidthViolation);
            }
            
            ring_elements.push(ring_elem);
        }
        
        Ok(ring_elements)
    }
    
    // Unpack ring vector back to field vector
    fn unpack_from_ring(&self, ring_vector: &[RingElement<F>]) -> Vec<F> {
        ring_vector.iter()
            .flat_map(|elem| elem.coeffs.clone())
            .collect()
    }
    
    // Compute commitment cost based on bit-widths
    fn commitment_cost(&self, vector_len: usize, bit_widths: &[usize]) -> usize {
        let d = self.packing_degree;
        let field_bits = F::MODULUS_BITS;
        
        // Number of ring elements needed
        let num_ring_elems = (vector_len + d - 1) / d;
        
        // Average bit-width per ring element
        let total_bits: usize = bit_widths.iter().sum();
        let avg_bits_per_elem = total_bits / vector_len;
        
        // Cost scales with bit-width fraction
        let cost_per_ring_elem = (avg_bits_per_elem * d) / field_bits;
        
        num_ring_elems * cost_per_ring_elem * self.ajtai.kappa
    }
}

struct VectorCommitment<F: Field> {
    commitment: Commitment<F>,
    original_length: usize,
    bit_widths: Vec<usize>,
}
```


#### 3.3 Evaluation Claims and Folding

```rust
struct EvaluationClaim<F: Field> {
    commitment: VectorCommitment<F>,
    point: Vec<F>,      // Evaluation point r ∈ F^ℓ
    value: F,           // Claimed value y = w̃(r)
}

impl<F: Field> EvaluationClaim<F> {
    // Verify claim: check that w̃(r) = y for witness w
    fn verify(&self, witness: &[F]) -> bool {
        assert_eq!(witness.len(), self.commitment.original_length);
        
        let mle = MultilinearPolynomial::new(witness.to_vec());
        let evaluated = mle.evaluate(&self.point);
        
        evaluated == self.value
    }
    
    // Fold multiple evaluation claims into one
    fn fold_claims(
        claims: &[Self],
        witnesses: &[Vec<F>],
        challenge: &[RingElement<F>],
    ) -> Result<(Self, Vec<F>), Error> {
        assert_eq!(claims.len(), witnesses.len());
        assert_eq!(claims.len(), challenge.len());
        
        // All claims must have same evaluation point
        let point = &claims[0].point;
        for claim in claims {
            if claim.point != *point {
                return Err(Error::MismatchedEvaluationPoints);
            }
        }
        
        // Compute folded commitment: C' = Σᵢ αᵢ·Cᵢ
        let commitments: Vec<_> = claims.iter()
            .map(|c| c.commitment.commitment.clone())
            .collect();
        let folded_commitment = Commitment::linear_combination(&commitments, challenge);
        
        // Compute folded value: y' = Σᵢ αᵢ·yᵢ
        let mut folded_value = F::zero();
        for (claim, alpha) in claims.iter().zip(challenge.iter()) {
            // Convert ring element to field element (constant term)
            let alpha_field = alpha.constant_term();
            folded_value = folded_value.add(&claim.value.mul(&alpha_field));
        }
        
        // Compute folded witness: w' = Σᵢ αᵢ·wᵢ
        let witness_len = witnesses[0].len();
        let mut folded_witness = vec![F::zero(); witness_len];
        
        for (witness, alpha) in witnesses.iter().zip(challenge.iter()) {
            let alpha_field = alpha.constant_term();
            for (i, w_i) in witness.iter().enumerate() {
                folded_witness[i] = folded_witness[i].add(&w_i.mul(&alpha_field));
            }
        }
        
        let folded_claim = EvaluationClaim {
            commitment: VectorCommitment {
                commitment: folded_commitment,
                original_length: witness_len,
                bit_widths: claims[0].commitment.bit_widths.clone(),
            },
            point: point.clone(),
            value: folded_value,
        };
        
        Ok((folded_claim, folded_witness))
    }
    
    // Compute cross-terms for folding verification
    fn compute_cross_terms(witnesses: &[Vec<F>]) -> Vec<F> {
        let k = witnesses.len();
        let mut cross_terms = Vec::new();
        
        // Compute σᵢⱼ = ⟨wᵢ, wⱼ⟩ for i < j
        for i in 0..k {
            for j in (i+1)..k {
                let inner_product = witnesses[i].iter()
                    .zip(witnesses[j].iter())
                    .map(|(a, b)| a.mul(b))
                    .fold(F::zero(), |acc, x| acc.add(&x));
                cross_terms.push(inner_product);
            }
        }
        
        cross_terms
    }
    
    // Verify cross-term consistency after folding
    fn verify_cross_terms(
        folded_witness: &[F],
        original_values: &[F],
        cross_terms: &[F],
        challenge: &[F],
    ) -> bool {
        // Compute ⟨w', w'⟩
        let folded_inner = folded_witness.iter()
            .map(|x| x.mul(x))
            .fold(F::zero(), |acc, x| acc.add(&x));
        
        // Compute expected: Σᵢ αᵢ²·yᵢ² + 2·Σᵢ<ⱼ αᵢαⱼ·σᵢⱼ
        let mut expected = F::zero();
        
        // Diagonal terms
        for (i, (alpha_i, y_i)) in challenge.iter().zip(original_values.iter()).enumerate() {
            let term = alpha_i.mul(alpha_i).mul(&y_i.mul(y_i));
            expected = expected.add(&term);
        }
        
        // Cross terms
        let mut cross_idx = 0;
        for i in 0..challenge.len() {
            for j in (i+1)..challenge.len() {
                let term = challenge[i].mul(&challenge[j])
                    .mul(&cross_terms[cross_idx])
                    .mul(&F::from_u64(2));
                expected = expected.add(&term);
                cross_idx += 1;
            }
        }
        
        folded_inner == expected
    }
}
```


### 4. CCS and Constraint System Layer

#### 4.1 CCS Structure Definition

```rust
struct CCSStructure<F: Field> {
    m: usize,                    // Number of constraints
    n: usize,                    // Number of variables
    n_padded: usize,             // N = 2^ℓ (padded to power of 2)
    ell: usize,                  // ℓ = log₂(N)
    t: usize,                    // Number of matrices
    q: usize,                    // Number of multilinear terms
    d: usize,                    // Maximum degree
    matrices: Vec<SparseMatrix<F>>,  // M₀, ..., M_{t-1}
    selectors: Vec<Vec<usize>>,  // S₀, ..., S_{q-1} (subsets of [t])
    constants: Vec<F>,           // c₀, ..., c_{q-1}
}

struct SparseMatrix<F: Field> {
    rows: usize,
    cols: usize,
    entries: Vec<(usize, usize, F)>,  // (row, col, value) triples
}

impl<F: Field> SparseMatrix<F> {
    // Matrix-vector multiplication
    fn mul_vector(&self, vec: &[F]) -> Vec<F> {
        assert_eq!(vec.len(), self.cols);
        let mut result = vec![F::zero(); self.rows];
        
        for (row, col, val) in &self.entries {
            result[*row] = result[*row].add(&val.mul(&vec[*col]));
        }
        
        result
    }
    
    // Multilinear extension of matrix
    fn to_mle(&self) -> MultilinearPolynomial<F> {
        // Flatten matrix to vector (row-major order)
        let mut flat = vec![F::zero(); self.rows * self.cols];
        for (row, col, val) in &self.entries {
            flat[row * self.cols + col] = *val;
        }
        
        // Pad to power of 2
        let padded_len = flat.len().next_power_of_two();
        flat.resize(padded_len, F::zero());
        
        MultilinearPolynomial::new(flat)
    }
}

struct CCSInstance<F: Field> {
    structure: CCSStructure<F>,
    public_input: Vec<F>,  // x ∈ F^ℓ
}

struct CCSWitness<F: Field> {
    private_witness: Vec<F>,  // w ∈ F^{n-ℓ-1}
}

impl<F: Field> CCSInstance<F> {
    // Construct full witness: z = (1, x, w)
    fn full_witness(&self, witness: &CCSWitness<F>) -> Vec<F> {
        let mut z = Vec::with_capacity(self.structure.n);
        z.push(F::one());
        z.extend_from_slice(&self.public_input);
        z.extend_from_slice(&witness.private_witness);
        
        // Pad to N = 2^ℓ
        z.resize(self.structure.n_padded, F::zero());
        z
    }
    
    // Verify CCS relation: Σᵢ cᵢ · (⊙ⱼ∈Sᵢ Mⱼz) = 0
    fn verify(&self, witness: &CCSWitness<F>) -> bool {
        let z = self.full_witness(witness);
        
        // Compute each matrix-vector product
        let mut products = Vec::new();
        for matrix in &self.structure.matrices {
            products.push(matrix.mul_vector(&z));
        }
        
        // Compute weighted sum of Hadamard products
        let mut result = vec![F::zero(); self.structure.m];
        
        for (i, selector) in self.structure.selectors.iter().enumerate() {
            // Compute Hadamard product: ⊙ⱼ∈Sᵢ Mⱼz
            let mut hadamard = vec![F::one(); self.structure.m];
            for &j in selector {
                for k in 0..self.structure.m {
                    hadamard[k] = hadamard[k].mul(&products[j][k]);
                }
            }
            
            // Add weighted term: cᵢ · hadamard
            let coeff = self.structure.constants[i];
            for k in 0..self.structure.m {
                result[k] = result[k].add(&coeff.mul(&hadamard[k]));
            }
        }
        
        // Check if result is zero vector
        result.iter().all(|x| *x == F::zero())
    }
}
```


#### 4.2 Sum-Check Protocol Implementation

```rust
struct SumCheckProver<F: Field> {
    polynomial: Box<dyn Fn(&[F]) -> F>,  // The polynomial g(x₁, ..., xₗ)
    num_vars: usize,
    degree: usize,
}

struct SumCheckVerifier<F: Field> {
    num_vars: usize,
    degree: usize,
    claimed_sum: F,
}

struct SumCheckProof<F: Field> {
    round_polynomials: Vec<Vec<F>>,  // Each round: evaluations at 0, 1, ..., d
    final_point: Vec<F>,             // Random point r ∈ F^ℓ
}

impl<F: Field> SumCheckProver<F> {
    fn new(polynomial: Box<dyn Fn(&[F]) -> F>, num_vars: usize, degree: usize) -> Self {
        Self {
            polynomial,
            num_vars,
            degree,
        }
    }
    
    // Run sum-check protocol
    fn prove(&self, transcript: &mut Transcript) -> SumCheckProof<F> {
        let mut round_polynomials = Vec::new();
        let mut challenges = Vec::new();
        
        // Compute initial sum over Boolean hypercube
        let mut current_sum = self.compute_sum_over_hypercube(&[]);
        
        for round in 0..self.num_vars {
            // Compute round polynomial sᵢ(X)
            let round_poly = self.compute_round_polynomial(round, &challenges);
            
            // Send evaluations: sᵢ(0), sᵢ(1), ..., sᵢ(d)
            let evaluations: Vec<F> = (0..=self.degree)
                .map(|j| self.evaluate_round_poly(&round_poly, j, round, &challenges))
                .collect();
            
            // Add to transcript and get challenge
            transcript.append_field_elements(&evaluations);
            let challenge = transcript.challenge_field_element();
            
            challenges.push(challenge);
            round_polynomials.push(evaluations);
        }
        
        SumCheckProof {
            round_polynomials,
            final_point: challenges,
        }
    }
    
    // Compute univariate polynomial for round i
    fn compute_round_polynomial(&self, round: usize, prev_challenges: &[F]) 
        -> Vec<F> {
        let remaining_vars = self.num_vars - round - 1;
        let num_points = 1 << remaining_vars;
        
        // For each value of Xᵢ ∈ {0, 1, ..., d}, sum over remaining variables
        let mut evaluations = Vec::new();
        
        for x_i in 0..=self.degree {
            let mut sum = F::zero();
            
            // Iterate over all assignments to remaining variables
            for assignment in 0..num_points {
                let mut point = prev_challenges.to_vec();
                point.push(F::from_u64(x_i as u64));
                
                // Add remaining variable assignments
                for j in 0..remaining_vars {
                    let bit = (assignment >> j) & 1;
                    point.push(F::from_u64(bit as u64));
                }
                
                sum = sum.add(&(self.polynomial)(&point));
            }
            
            evaluations.push(sum);
        }
        
        evaluations
    }
    
    fn evaluate_round_poly(&self, poly: &[F], x: usize, round: usize, 
                          prev_challenges: &[F]) -> F {
        poly[x]
    }
    
    fn compute_sum_over_hypercube(&self, fixed_vars: &[F]) -> F {
        let remaining = self.num_vars - fixed_vars.len();
        let num_points = 1 << remaining;
        
        let mut sum = F::zero();
        for i in 0..num_points {
            let mut point = fixed_vars.to_vec();
            for j in 0..remaining {
                let bit = (i >> j) & 1;
                point.push(F::from_u64(bit as u64));
            }
            sum = sum.add(&(self.polynomial)(&point));
        }
        
        sum
    }
}

impl<F: Field> SumCheckVerifier<F> {
    fn verify(&mut self, proof: &SumCheckProof<F>, transcript: &mut Transcript) 
        -> Result<(Vec<F>, F), Error> {
        let mut current_sum = self.claimed_sum;
        let mut challenges = Vec::new();
        
        for (round, evaluations) in proof.round_polynomials.iter().enumerate() {
            // Check degree
            if evaluations.len() != self.degree + 1 {
                return Err(Error::InvalidDegree);
            }
            
            // Check consistency: sᵢ(0) + sᵢ(1) = previous sum
            let sum_check = evaluations[0].add(&evaluations[1]);
            if sum_check != current_sum {
                return Err(Error::SumCheckFailed);
            }
            
            // Add to transcript and get challenge
            transcript.append_field_elements(evaluations);
            let challenge = transcript.challenge_field_element();
            
            // Evaluate at challenge point
            current_sum = self.evaluate_univariate(evaluations, &challenge);
            challenges.push(challenge);
        }
        
        Ok((challenges, current_sum))
    }
    
    // Lagrange interpolation to evaluate univariate polynomial
    fn evaluate_univariate(&self, evaluations: &[F], point: &F) -> F {
        let d = evaluations.len() - 1;
        let mut result = F::zero();
        
        for i in 0..=d {
            let mut term = evaluations[i];
            
            // Compute Lagrange basis polynomial L_i(point)
            for j in 0..=d {
                if i != j {
                    let numerator = point.sub(&F::from_u64(j as u64));
                    let denominator = F::from_u64(i as u64)
                        .sub(&F::from_u64(j as u64));
                    term = term.mul(&numerator.mul(&denominator.inv().unwrap()));
                }
            }
            
            result = result.add(&term);
        }
        
        result
    }
}
```


#### 4.3 CCS to Evaluation Claims Reduction

```rust
struct CCSReduction<F: Field> {
    commitment_scheme: MatrixCommitmentScheme<F>,
}

impl<F: Field> CCSReduction<F> {
    // Reduce CCS instance to multilinear evaluation claims
    fn reduce(
        &mut self,
        instance: &CCSInstance<F>,
        witness: &CCSWitness<F>,
        transcript: &mut Transcript,
    ) -> Result<Vec<EvaluationClaim<F>>, Error> {
        let z = instance.full_witness(witness);
        
        // Commit to witness
        let bit_widths = vec![F::MODULUS_BITS; z.len()];
        let z_commitment = self.commitment_scheme.commit_vector(&z, &bit_widths)?;
        
        // Define CCS polynomial: g(x) = Σᵢ cᵢ · ∏ⱼ∈Sᵢ (Mⱼz)~(x)
        let ccs_poly = self.construct_ccs_polynomial(instance, &z);
        
        // Run sum-check on: Σₓ∈{0,1}^ℓ g(x) = 0
        let sum_check_prover = SumCheckProver::new(
            Box::new(ccs_poly),
            instance.structure.ell,
            instance.structure.d,
        );
        
        let proof = sum_check_prover.prove(transcript);
        let final_point = proof.final_point.clone();
        
        // Generate evaluation claims for each matrix
        let mut claims = Vec::new();
        
        for (j, matrix) in instance.structure.matrices.iter().enumerate() {
            // Compute (Mⱼz)~(r)
            let mj_z = matrix.mul_vector(&z);
            let mj_z_mle = MultilinearPolynomial::new(mj_z);
            let value = mj_z_mle.evaluate(&final_point);
            
            claims.push(EvaluationClaim {
                commitment: z_commitment.clone(),
                point: final_point.clone(),
                value,
            });
        }
        
        Ok(claims)
    }
    
    // Construct CCS polynomial for sum-check
    fn construct_ccs_polynomial(
        &self,
        instance: &CCSInstance<F>,
        z: &[F],
    ) -> impl Fn(&[F]) -> F {
        let structure = instance.structure.clone();
        let z_clone = z.to_vec();
        
        move |point: &[F]| -> F {
            let mut result = F::zero();
            
            // Compute each matrix-vector product MLE
            let mut mj_z_mles = Vec::new();
            for matrix in &structure.matrices {
                let mj_z = matrix.mul_vector(&z_clone);
                mj_z_mles.push(MultilinearPolynomial::new(mj_z));
            }
            
            // Compute g(point) = Σᵢ cᵢ · ∏ⱼ∈Sᵢ (Mⱼz)~(point)
            for (i, selector) in structure.selectors.iter().enumerate() {
                let mut term = structure.constants[i];
                
                for &j in selector {
                    let eval = mj_z_mles[j].evaluate(point);
                    term = term.mul(&eval);
                }
                
                result = result.add(&term);
            }
            
            result
        }
    }
}
```


### 5. Folding Scheme Layer

#### 5.1 Witness Decomposition

```rust
struct WitnessDecomposition<F: Field> {
    base: u64,           // Decomposition base b
    num_digits: usize,   // ℓ = ⌈log_b(B)⌉
    norm_bound: u64,     // Original norm bound B
}

impl<F: Field> WitnessDecomposition<F> {
    fn new(norm_bound: u64) -> Self {
        // Choose base b ≈ √B for optimal balance
        let base = (norm_bound as f64).sqrt().ceil() as u64;
        let num_digits = ((norm_bound as f64).log(base as f64)).ceil() as usize;
        
        Self {
            base,
            num_digits,
            norm_bound,
        }
    }
    
    // Decompose witness w into base-b digits: w = Σⱼ b^j · wⱼ
    fn decompose(&self, witness: &[F]) -> Result<Vec<Vec<F>>, Error> {
        let mut digits = vec![Vec::new(); self.num_digits];
        
        for &w_i in witness {
            // Convert to signed integer representation
            let val = w_i.to_canonical_u64();
            let signed_val = if val <= F::MODULUS / 2 {
                val as i64
            } else {
                (val as i64) - (F::MODULUS as i64)
            };
            
            // Check norm bound
            if signed_val.abs() as u64 > self.norm_bound {
                return Err(Error::NormBoundViolation);
            }
            
            // Decompose into base-b digits (balanced representation)
            let mut remaining = signed_val;
            for digit_vec in &mut digits {
                let digit = Self::balanced_digit(remaining, self.base as i64);
                remaining = (remaining - digit) / (self.base as i64);
                
                // Convert back to field element
                let digit_field = if digit >= 0 {
                    F::from_u64(digit as u64)
                } else {
                    F::from_u64((-digit) as u64).neg()
                };
                
                digit_vec.push(digit_field);
            }
            
            // Verify decomposition
            assert_eq!(remaining, 0, "Decomposition failed");
        }
        
        Ok(digits)
    }
    
    // Balanced digit extraction: digit ∈ [-b/2, b/2)
    fn balanced_digit(value: i64, base: i64) -> i64 {
        let mut digit = value % base;
        if digit > base / 2 {
            digit -= base;
        } else if digit < -(base / 2) {
            digit += base;
        }
        digit
    }
    
    // Reconstruct witness from digits
    fn reconstruct(&self, digits: &[Vec<F>]) -> Vec<F> {
        assert_eq!(digits.len(), self.num_digits);
        let len = digits[0].len();
        
        let mut result = vec![F::zero(); len];
        let mut base_power = F::one();
        
        for digit_vec in digits {
            assert_eq!(digit_vec.len(), len);
            
            for (i, &digit) in digit_vec.iter().enumerate() {
                result[i] = result[i].add(&digit.mul(&base_power));
            }
            
            base_power = base_power.mul(&F::from_u64(self.base));
        }
        
        result
    }
    
    // Verify each digit has small norm
    fn verify_digit_norms(&self, digits: &[Vec<F>]) -> bool {
        let max_digit = self.base / 2;
        
        for digit_vec in digits {
            for &digit in digit_vec {
                let val = digit.to_canonical_u64();
                let signed_val = if val <= F::MODULUS / 2 {
                    val
                } else {
                    F::MODULUS - val
                };
                
                if signed_val > max_digit {
                    return false;
                }
            }
        }
        
        true
    }
}
```


#### 5.2 Random Linear Combination (RLC) Reduction

```rust
struct RLCReduction<F: Field> {
    challenge_set: ChallengeSet<F>,
}

struct ChallengeSet<F: Field> {
    ring: CyclotomicRing<F>,
    elements: Vec<RingElement<F>>,
    norm_bound: u64,
}

impl<F: Field> ChallengeSet<F> {
    // Create challenge set with ternary coefficients: {-1, 0, 1}
    fn new_ternary(ring: CyclotomicRing<F>) -> Self {
        let d = ring.degree;
        
        // For security, need |C| ≥ 2^128
        // With ternary coefficients: |C| = 3^d
        // Need d ≥ 81 for 128-bit security (3^81 ≈ 2^128)
        assert!(d >= 81, "Ring degree too small for 128-bit security");
        
        // Generate all ternary combinations (in practice, sample on demand)
        let elements = Vec::new(); // Populated lazily
        
        Self {
            ring,
            elements,
            norm_bound: 1, // ||c||_∞ = 1 for ternary
        }
    }
    
    // Sample random challenge from set
    fn sample_challenge(&self, transcript: &mut Transcript) -> RingElement<F> {
        let d = self.ring.degree;
        let mut coeffs = Vec::with_capacity(d);
        
        for i in 0..d {
            // Get random bytes from transcript
            let bytes = transcript.challenge_bytes(1);
            let val = bytes[0] % 3;
            
            let coeff = match val {
                0 => F::zero(),
                1 => F::one(),
                2 => F::one().neg(),
                _ => unreachable!(),
            };
            
            coeffs.push(coeff);
        }
        
        RingElement { coeffs }
    }
    
    // Verify challenge is in set
    fn verify_challenge(&self, challenge: &RingElement<F>) -> bool {
        // Check all coefficients are in {-1, 0, 1}
        for coeff in &challenge.coeffs {
            let val = coeff.to_canonical_u64();
            if val != 0 && val != 1 && val != F::MODULUS - 1 {
                return false;
            }
        }
        
        // Check norm bound
        challenge.norm_infinity() <= self.norm_bound
    }
    
    // Check invertibility: c - c' is invertible for all c ≠ c'
    fn check_invertibility(&self, c1: &RingElement<F>, c2: &RingElement<F>) -> bool {
        let diff = self.ring.sub(c1, c2);
        
        // Use Theorem 1: if ||cf(a)||_∞ < b_inv, then a is invertible
        // For Goldilocks with d=64, e=2: b_inv = q^(1/2) / √2
        let q = F::MODULUS as f64;
        let b_inv = (q.sqrt() / 2.0_f64.sqrt()) as u64;
        
        diff.norm_infinity() < b_inv
    }
}

impl<F: Field> RLCReduction<F> {
    // Reduce L evaluation claims to single claim
    fn reduce(
        &self,
        claims: &[EvaluationClaim<F>],
        witnesses: &[Vec<F>],
        transcript: &mut Transcript,
    ) -> Result<(EvaluationClaim<F>, Vec<F>), Error> {
        let L = claims.len();
        assert_eq!(witnesses.len(), L);
        
        // Sample random coefficients ρ ∈ C^L
        let mut challenges = Vec::new();
        for _ in 0..L {
            let challenge = self.challenge_set.sample_challenge(transcript);
            challenges.push(challenge);
        }
        
        // Fold claims using challenges
        EvaluationClaim::fold_claims(claims, witnesses, &challenges)
    }
}
```


#### 5.3 Complete Neo Folding Scheme

```rust
struct NeoFoldingScheme<F: Field> {
    commitment_scheme: MatrixCommitmentScheme<F>,
    ccs_reduction: CCSReduction<F>,
    rlc_reduction: RLCReduction<F>,
    decomposition: WitnessDecomposition<F>,
}

impl<F: Field> NeoFoldingScheme<F> {
    fn new(
        ring: CyclotomicRing<F>,
        kappa: usize,
        norm_bound: u64,
    ) -> Self {
        let commitment_scheme = MatrixCommitmentScheme::new(
            ring.clone(),
            kappa,
            norm_bound,
        );
        
        let challenge_set = ChallengeSet::new_ternary(ring);
        
        Self {
            commitment_scheme: commitment_scheme.clone(),
            ccs_reduction: CCSReduction { commitment_scheme },
            rlc_reduction: RLCReduction { challenge_set },
            decomposition: WitnessDecomposition::new(norm_bound),
        }
    }
    
    // Fold two CCS instances into one
    fn fold(
        &mut self,
        instance1: &CCSInstance<F>,
        witness1: &CCSWitness<F>,
        instance2: &CCSInstance<F>,
        witness2: &CCSWitness<F>,
        transcript: &mut Transcript,
    ) -> Result<(EvaluationClaim<F>, Vec<F>), Error> {
        // Phase 1: CCS to Evaluation Claims (both instances)
        let claims1 = self.ccs_reduction.reduce(instance1, witness1, transcript)?;
        let claims2 = self.ccs_reduction.reduce(instance2, witness2, transcript)?;
        
        // Combine claims from both instances
        let mut all_claims = claims1;
        all_claims.extend(claims2);
        
        // Get corresponding witnesses
        let z1 = instance1.full_witness(witness1);
        let z2 = instance2.full_witness(witness2);
        let mut all_witnesses = vec![z1, z2];
        
        // Phase 2: Random Linear Combination
        let (combined_claim, combined_witness) = self.rlc_reduction.reduce(
            &all_claims,
            &all_witnesses,
            transcript,
        )?;
        
        // Phase 3: Decomposition
        let digit_witnesses = self.decomposition.decompose(&combined_witness)?;
        
        // Create evaluation claims for each digit
        let mut digit_claims = Vec::new();
        for digit_witness in &digit_witnesses {
            let bit_widths = vec![
                (self.decomposition.base as f64).log2().ceil() as usize;
                digit_witness.len()
            ];
            
            let commitment = self.commitment_scheme.commit_vector(
                digit_witness,
                &bit_widths,
            )?;
            
            let mle = MultilinearPolynomial::new(digit_witness.clone());
            let value = mle.evaluate(&combined_claim.point);
            
            digit_claims.push(EvaluationClaim {
                commitment,
                point: combined_claim.point.clone(),
                value,
            });
        }
        
        // Phase 4: Fold digit claims
        let (final_claim, final_witness) = self.rlc_reduction.reduce(
            &digit_claims,
            &digit_witnesses,
            transcript,
        )?;
        
        // Verify final witness has small norm
        let final_norm = final_witness.iter()
            .map(|x| {
                let val = x.to_canonical_u64();
                if val <= F::MODULUS / 2 { val } else { F::MODULUS - val }
            })
            .max()
            .unwrap_or(0);
        
        if final_norm > self.decomposition.base / 2 {
            return Err(Error::NormBoundViolation);
        }
        
        Ok((final_claim, final_witness))
    }
    
    // Verify folding proof
    fn verify(
        &self,
        instance1: &CCSInstance<F>,
        instance2: &CCSInstance<F>,
        final_claim: &EvaluationClaim<F>,
        transcript: &mut Transcript,
    ) -> Result<bool, Error> {
        // Verifier only needs to:
        // 1. Verify sum-check proofs (O(log N) time)
        // 2. Compute folded commitment (O(κ) time)
        // 3. Check final evaluation claim
        
        // This is much cheaper than re-running the prover
        Ok(true) // Simplified verification
    }
}
```


### 6. IVC/PCD Construction

#### 6.1 Incrementally Verifiable Computation

```rust
struct IVCProof<F: Field> {
    accumulator: EvaluationClaim<F>,
    accumulator_witness: Vec<F>,
    step_count: usize,
}

struct IVCScheme<F: Field> {
    folding_scheme: NeoFoldingScheme<F>,
    step_circuit: CCSStructure<F>,
}

impl<F: Field> IVCScheme<F> {
    fn new(
        folding_scheme: NeoFoldingScheme<F>,
        step_circuit: CCSStructure<F>,
    ) -> Self {
        Self {
            folding_scheme,
            step_circuit,
        }
    }
    
    // Initialize IVC with first step
    fn init(
        &mut self,
        initial_state: &[F],
        initial_witness: &CCSWitness<F>,
        transcript: &mut Transcript,
    ) -> Result<IVCProof<F>, Error> {
        let instance = CCSInstance {
            structure: self.step_circuit.clone(),
            public_input: initial_state.to_vec(),
        };
        
        // Create initial evaluation claim
        let z = instance.full_witness(initial_witness);
        let bit_widths = vec![F::MODULUS_BITS; z.len()];
        let commitment = self.folding_scheme.commitment_scheme
            .commit_vector(&z, &bit_widths)?;
        
        let mle = MultilinearPolynomial::new(z.clone());
        let point = vec![F::zero(); self.step_circuit.ell];
        let value = mle.evaluate(&point);
        
        let accumulator = EvaluationClaim {
            commitment,
            point,
            value,
        };
        
        Ok(IVCProof {
            accumulator,
            accumulator_witness: z,
            step_count: 1,
        })
    }
    
    // Prove one step of computation
    fn prove_step(
        &mut self,
        proof: &IVCProof<F>,
        next_state: &[F],
        step_witness: &CCSWitness<F>,
        transcript: &mut Transcript,
    ) -> Result<IVCProof<F>, Error> {
        // Create instance for current step
        let step_instance = CCSInstance {
            structure: self.step_circuit.clone(),
            public_input: next_state.to_vec(),
        };
        
        // Verify step is correct
        if !step_instance.verify(step_witness) {
            return Err(Error::InvalidStep);
        }
        
        // Create dummy instance for accumulator (to fold with)
        let acc_instance = CCSInstance {
            structure: self.step_circuit.clone(),
            public_input: vec![F::zero(); next_state.len()],
        };
        
        let acc_witness = CCSWitness {
            private_witness: proof.accumulator_witness[1 + next_state.len()..].to_vec(),
        };
        
        // Fold step with accumulator
        let (new_accumulator, new_witness) = self.folding_scheme.fold(
            &acc_instance,
            &acc_witness,
            &step_instance,
            step_witness,
            transcript,
        )?;
        
        Ok(IVCProof {
            accumulator: new_accumulator,
            accumulator_witness: new_witness,
            step_count: proof.step_count + 1,
        })
    }
    
    // Verify IVC proof
    fn verify(
        &self,
        proof: &IVCProof<F>,
        initial_state: &[F],
        final_state: &[F],
        transcript: &mut Transcript,
    ) -> Result<bool, Error> {
        // Verify accumulator is valid
        let is_valid = proof.accumulator.verify(&proof.accumulator_witness);
        
        if !is_valid {
            return Ok(false);
        }
        
        // Verify state transitions (encoded in accumulator)
        // This is implicit in the folding verification
        
        Ok(true)
    }
}
```


#### 6.2 Proof Compression with SNARK

```rust
struct CompressedProof<F: Field> {
    accumulator_commitment: VectorCommitment<F>,
    final_state: Vec<F>,
    snark_proof: Vec<u8>,  // Serialized SNARK proof
}

struct ProofCompressor<F: Field> {
    ivc_scheme: IVCScheme<F>,
}

impl<F: Field> ProofCompressor<F> {
    // Compress IVC proof using SNARK
    fn compress(
        &self,
        ivc_proof: &IVCProof<F>,
        transcript: &mut Transcript,
    ) -> Result<CompressedProof<F>, Error> {
        // Define relation for accumulator validity
        // R_acc: (C, r, y, w) where C = Com(w) and w̃(r) = y
        
        // For post-quantum security, use lattice-based or hash-based SNARK
        // Options:
        // 1. Spartan + FRI (hash-based, post-quantum)
        // 2. Another lattice-based SNARK
        // 3. STARKs (hash-based, post-quantum)
        
        // Here we outline Spartan + FRI approach
        let snark_proof = self.compress_with_spartan_fri(ivc_proof)?;
        
        Ok(CompressedProof {
            accumulator_commitment: ivc_proof.accumulator.commitment.clone(),
            final_state: vec![], // Extract from accumulator
            snark_proof,
        })
    }
    
    fn compress_with_spartan_fri(
        &self,
        ivc_proof: &IVCProof<F>,
    ) -> Result<Vec<u8>, Error> {
        // Step 1: Express accumulator relation as R1CS or CCS
        // Step 2: Use Spartan to reduce to multilinear evaluation claims
        // Step 3: Use FRI to prove evaluations
        
        // This provides:
        // - Post-quantum security (FRI is hash-based)
        // - No wrong-field arithmetic (native field support)
        // - Proof size: O(log N) where N is witness size
        
        // Placeholder for actual implementation
        Ok(vec![])
    }
    
    // Verify compressed proof
    fn verify_compressed(
        &self,
        proof: &CompressedProof<F>,
        initial_state: &[F],
        final_state: &[F],
    ) -> Result<bool, Error> {
        // Verify SNARK proof for accumulator relation
        // This is much faster than verifying full IVC proof
        
        // Verification time: O(log N) for Spartan + FRI
        // vs O(num_steps · log N) for full IVC verification
        
        Ok(true) // Placeholder
    }
}
```


### 7. Transcript and Fiat-Shamir

#### 7.1 Transcript Implementation

```rust
use sha3::{Sha3_256, Digest};

struct Transcript {
    hasher: Sha3_256,
    challenge_counter: usize,
}

impl Transcript {
    fn new(label: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(label);
        
        Self {
            hasher,
            challenge_counter: 0,
        }
    }
    
    // Append field element to transcript
    fn append_field_element<F: Field>(&mut self, element: &F) {
        let bytes = element.to_canonical_u64().to_le_bytes();
        self.hasher.update(&bytes);
    }
    
    // Append multiple field elements
    fn append_field_elements<F: Field>(&mut self, elements: &[F]) {
        for elem in elements {
            self.append_field_element(elem);
        }
    }
    
    // Append commitment to transcript
    fn append_commitment<F: Field>(&mut self, commitment: &Commitment<F>) {
        for ring_elem in &commitment.values {
            for coeff in &ring_elem.coeffs {
                self.append_field_element(coeff);
            }
        }
    }
    
    // Get challenge field element
    fn challenge_field_element<F: Field>(&mut self) -> F {
        self.challenge_counter += 1;
        
        // Hash current state with counter
        let mut challenge_hasher = self.hasher.clone();
        challenge_hasher.update(&self.challenge_counter.to_le_bytes());
        let hash = challenge_hasher.finalize();
        
        // Convert hash to field element
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash[0..8]);
        let value = u64::from_le_bytes(bytes);
        
        F::from_u64(value % F::MODULUS)
    }
    
    // Get challenge bytes
    fn challenge_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        self.challenge_counter += 1;
        
        let mut challenge_hasher = self.hasher.clone();
        challenge_hasher.update(&self.challenge_counter.to_le_bytes());
        let hash = challenge_hasher.finalize();
        
        hash[0..num_bytes].to_vec()
    }
    
    // Get challenge ring element
    fn challenge_ring_element<F: Field>(
        &mut self,
        ring: &CyclotomicRing<F>,
    ) -> RingElement<F> {
        let mut coeffs = Vec::with_capacity(ring.degree);
        
        for _ in 0..ring.degree {
            coeffs.push(self.challenge_field_element());
        }
        
        RingElement { coeffs }
    }
}
```


## Data Models

### Core Data Structures

```rust
// Field element wrapper
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FieldElement<F: Field> {
    value: u64,
    _phantom: PhantomData<F>,
}

// Ring element
#[derive(Clone, Debug, PartialEq)]
struct RingElement<F: Field> {
    coeffs: Vec<F>,
}

// Commitment
#[derive(Clone, Debug)]
struct Commitment<F: Field> {
    values: Vec<RingElement<F>>,
    scheme: AjtaiCommitmentScheme<F>,
}

// Evaluation claim
#[derive(Clone, Debug)]
struct EvaluationClaim<F: Field> {
    commitment: VectorCommitment<F>,
    point: Vec<F>,
    value: F,
}

// CCS instance
#[derive(Clone, Debug)]
struct CCSInstance<F: Field> {
    structure: CCSStructure<F>,
    public_input: Vec<F>,
}

// CCS witness
#[derive(Clone, Debug)]
struct CCSWitness<F: Field> {
    private_witness: Vec<F>,
}

// Folding proof
#[derive(Clone, Debug)]
struct FoldingProof<F: Field> {
    sum_check_proofs: Vec<SumCheckProof<F>>,
    cross_terms: Vec<F>,
    final_claim: EvaluationClaim<F>,
}
```

### Parameter Sets

```rust
#[derive(Clone, Debug)]
struct NeoParameters {
    // Field parameters
    field_type: FieldType,
    field_modulus: u64,
    
    // Ring parameters
    ring_degree: usize,           // d
    cyclotomic_index: usize,      // η
    extension_degree: usize,      // τ = d/e
    
    // Commitment parameters
    commitment_dimension: usize,  // κ
    norm_bound: u64,              // β
    
    // Security parameters
    security_level: usize,        // λ (bits)
    challenge_set_size: usize,    // |C|
    
    // Decomposition parameters
    decomposition_base: u64,      // b
    num_digits: usize,            // ℓ
}

enum FieldType {
    Goldilocks,
    Mersenne61,
    AlmostGoldilocks,
}

impl NeoParameters {
    // Goldilocks parameters for 128-bit security
    fn goldilocks_128() -> Self {
        Self {
            field_type: FieldType::Goldilocks,
            field_modulus: (1u64 << 64) - (1u64 << 32) + 1,
            ring_degree: 64,
            cyclotomic_index: 128,
            extension_degree: 32,
            commitment_dimension: 4,
            norm_bound: 1 << 20,
            security_level: 128,
            challenge_set_size: 1 << 128,
            decomposition_base: 1 << 10,
            num_digits: 2,
        }
    }
    
    // Mersenne 61 parameters for 128-bit security
    fn mersenne61_128() -> Self {
        Self {
            field_type: FieldType::Mersenne61,
            field_modulus: (1u64 << 61) - 1,
            ring_degree: 64,
            cyclotomic_index: 128,
            extension_degree: 64,
            commitment_dimension: 5,
            norm_bound: 1 << 18,
            security_level: 128,
            challenge_set_size: 1 << 128,
            decomposition_base: 1 << 9,
            num_digits: 2,
        }
    }
    
    // Validate parameters for security
    fn validate(&self) -> Result<(), Error> {
        // Check ring degree is power of 2
        if !self.ring_degree.is_power_of_two() {
            return Err(Error::InvalidParameters("Ring degree must be power of 2"));
        }
        
        // Check Module-SIS hardness
        let msis_bits = self.estimate_msis_security();
        if msis_bits < self.security_level {
            return Err(Error::InsufficientSecurity);
        }
        
        // Check challenge set size
        let challenge_bits = (self.challenge_set_size as f64).log2() as usize;
        if challenge_bits < self.security_level {
            return Err(Error::InsufficientSecurity);
        }
        
        Ok(())
    }
    
    fn estimate_msis_security(&self) -> usize {
        // Use lattice estimator formulas
        // implementation would use full lattice estimator
        let log_q = (self.field_modulus as f64).log2();
        let dimension = self.commitment_dimension * self.ring_degree;
        
        // BKZ block size estimate
        let block_size = (dimension as f64 * log_q / 2.0) as usize;
        
        // Security level ≈ block_size (simplified)
        block_size.min(256)
    }
}
```


## Error Handling

### Error Types

```rust
#[derive(Debug, Clone, PartialEq)]
enum Error {
    // Field arithmetic errors
    DivisionByZero,
    InvalidFieldElement,
    
    // Ring operation errors
    InvalidRingDegree,
    NTTNotAvailable,
    InvalidPolynomialDegree,
    
    // Commitment errors
    NormBoundViolation,
    InvalidCommitment,
    CommitmentMismatch,
    BitWidthViolation,
    
    // Folding errors
    MismatchedEvaluationPoints,
    InvalidStep,
    SumCheckFailed,
    InvalidDegree,
    CrossTermMismatch,
    
    // Security errors
    InsufficientSecurity,
    InvalidChallenge,
    InvalidParameters(&'static str),
    
    // Proof errors
    InvalidProof,
    VerificationFailed,
    
    // System errors
    OutOfMemory,
    InvalidInput(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::DivisionByZero => write!(f, "Division by zero"),
            Error::InvalidFieldElement => write!(f, "Invalid field element"),
            Error::InvalidRingDegree => write!(f, "Invalid ring degree"),
            Error::NTTNotAvailable => write!(f, "NTT not available for this field"),
            Error::InvalidPolynomialDegree => write!(f, "Invalid polynomial degree"),
            Error::NormBoundViolation => write!(f, "Witness norm exceeds bound"),
            Error::InvalidCommitment => write!(f, "Invalid commitment"),
            Error::CommitmentMismatch => write!(f, "Commitment does not match witness"),
            Error::BitWidthViolation => write!(f, "Value exceeds specified bit width"),
            Error::MismatchedEvaluationPoints => write!(f, "Evaluation points do not match"),
            Error::InvalidStep => write!(f, "Invalid IVC step"),
            Error::SumCheckFailed => write!(f, "Sum-check verification failed"),
            Error::InvalidDegree => write!(f, "Polynomial degree mismatch"),
            Error::CrossTermMismatch => write!(f, "Cross-term verification failed"),
            Error::InsufficientSecurity => write!(f, "Parameters do not provide sufficient security"),
            Error::InvalidChallenge => write!(f, "Challenge not in valid set"),
            Error::InvalidParameters(msg) => write!(f, "Invalid parameters: {}", msg),
            Error::InvalidProof => write!(f, "Invalid proof"),
            Error::VerificationFailed => write!(f, "Proof verification failed"),
            Error::OutOfMemory => write!(f, "Out of memory"),
            Error::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
        }
    }
}

impl std::error::Error for Error {}
```


## Performance Optimizations

### 1. SIMD and Vectorization

```rust
// Batch field operations using SIMD
#[cfg(target_arch = "x86_64")]
mod simd_ops {
    use std::arch::x86_64::*;
    
    // Batch addition for Goldilocks field
    pub unsafe fn batch_add_goldilocks(a: &[u64], b: &[u64], result: &mut [u64]) {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), result.len());
        
        const MODULUS: u64 = (1u64 << 64) - (1u64 << 32) + 1;
        
        let len = a.len();
        let chunks = len / 4;
        
        for i in 0..chunks {
            let idx = i * 4;
            
            // Load 4 elements at a time
            let va = _mm256_loadu_si256(a[idx..].as_ptr() as *const __m256i);
            let vb = _mm256_loadu_si256(b[idx..].as_ptr() as *const __m256i);
            
            // Add
            let vsum = _mm256_add_epi64(va, vb);
            
            // Store (reduction done separately)
            _mm256_storeu_si256(result[idx..].as_mut_ptr() as *mut __m256i, vsum);
        }
        
        // Handle remaining elements
        for i in (chunks * 4)..len {
            result[i] = a[i].wrapping_add(b[i]);
        }
        
        // Reduce all results
        for r in result.iter_mut() {
            if *r >= MODULUS {
                *r -= MODULUS;
            }
        }
    }
    
    // Batch multiplication for Goldilocks field
    pub unsafe fn batch_mul_goldilocks(a: &[u64], b: &[u64], result: &mut [u64]) {
        // Use Montgomery multiplication for efficiency
        for i in 0..a.len() {
            result[i] = montgomery_mul(a[i], b[i]);
        }
    }
    
    fn montgomery_mul(a: u64, b: u64) -> u64 {
        // Montgomery multiplication implementation
        const MODULUS: u64 = (1u64 << 64) - (1u64 << 32) + 1;
        const R: u128 = 1u128 << 64;
        
        let prod = (a as u128) * (b as u128);
        let reduced = (prod % (MODULUS as u128)) as u64;
        reduced
    }
}
```

### 2. NTT Optimizations

```rust
impl<F: Field> CyclotomicRing<F> {
    // Optimized NTT using precomputed twiddle factors
    fn ntt_forward_optimized(&self, coeffs: &[F]) -> Vec<F> {
        let n = coeffs.len();
        assert!(n.is_power_of_two());
        
        // Precompute twiddle factors
        let twiddles = self.precompute_twiddles(n);
        
        let mut result = coeffs.to_vec();
        
        // Bit-reversal permutation
        self.bit_reverse_permutation(&mut result);
        
        // Iterative FFT with precomputed twiddles
        let mut m = 2;
        while m <= n {
            let half_m = m / 2;
            
            for k in (0..n).step_by(m) {
                for j in 0..half_m {
                    let twiddle_idx = (n / m) * j;
                    let twiddle = twiddles[twiddle_idx];
                    
                    let u = result[k + j];
                    let t = twiddle.mul(&result[k + j + half_m]);
                    
                    result[k + j] = u.add(&t);
                    result[k + j + half_m] = u.sub(&t);
                }
            }
            
            m *= 2;
        }
        
        result
    }
    
    fn precompute_twiddles(&self, n: usize) -> Vec<F> {
        let omega = self.root_of_unity.unwrap();
        let mut twiddles = Vec::with_capacity(n);
        
        let mut current = F::one();
        for _ in 0..n {
            twiddles.push(current);
            current = current.mul(&omega);
        }
        
        twiddles
    }
    
    fn bit_reverse_permutation(&self, data: &mut [F]) {
        let n = data.len();
        let log_n = n.trailing_zeros() as usize;
        
        for i in 0..n {
            let j = Self::bit_reverse(i, log_n);
            if i < j {
                data.swap(i, j);
            }
        }
    }
    
    fn bit_reverse(mut x: usize, bits: usize) -> usize {
        let mut result = 0;
        for _ in 0..bits {
            result = (result << 1) | (x & 1);
            x >>= 1;
        }
        result
    }
}
```

### 3. Sparse Matrix Optimizations

```rust
impl<F: Field> SparseMatrix<F> {
    // Compressed sparse row (CSR) format
    fn to_csr(&self) -> CSRMatrix<F> {
        let mut row_ptr = vec![0; self.rows + 1];
        let mut col_indices = Vec::new();
        let mut values = Vec::new();
        
        // Sort entries by row
        let mut sorted_entries = self.entries.clone();
        sorted_entries.sort_by_key(|(row, _, _)| *row);
        
        let mut current_row = 0;
        for (row, col, val) in sorted_entries {
            while current_row < row {
                current_row += 1;
                row_ptr[current_row] = col_indices.len();
            }
            
            col_indices.push(col);
            values.push(val);
        }
        
        while current_row < self.rows {
            current_row += 1;
            row_ptr[current_row] = col_indices.len();
        }
        
        CSRMatrix {
            rows: self.rows,
            cols: self.cols,
            row_ptr,
            col_indices,
            values,
        }
    }
}

struct CSRMatrix<F: Field> {
    rows: usize,
    cols: usize,
    row_ptr: Vec<usize>,
    col_indices: Vec<usize>,
    values: Vec<F>,
}

impl<F: Field> CSRMatrix<F> {
    // Optimized sparse matrix-vector multiplication
    fn mul_vector(&self, vec: &[F]) -> Vec<F> {
        let mut result = vec![F::zero(); self.rows];
        
        for row in 0..self.rows {
            let start = self.row_ptr[row];
            let end = self.row_ptr[row + 1];
            
            let mut sum = F::zero();
            for idx in start..end {
                let col = self.col_indices[idx];
                let val = self.values[idx];
                sum = sum.add(&val.mul(&vec[col]));
            }
            
            result[row] = sum;
        }
        
        result
    }
}
```


### 4. Memory Management

```rust
// Memory pool for temporary allocations
struct MemoryPool<F: Field> {
    field_buffers: Vec<Vec<F>>,
    ring_buffers: Vec<Vec<RingElement<F>>>,
    max_size: usize,
}

impl<F: Field> MemoryPool<F> {
    fn new(max_size: usize) -> Self {
        Self {
            field_buffers: Vec::new(),
            ring_buffers: Vec::new(),
            max_size,
        }
    }
    
    fn get_field_buffer(&mut self, size: usize) -> Vec<F> {
        if let Some(mut buf) = self.field_buffers.pop() {
            buf.clear();
            buf.resize(size, F::zero());
            buf
        } else {
            vec![F::zero(); size]
        }
    }
    
    fn return_field_buffer(&mut self, buf: Vec<F>) {
        if self.field_buffers.len() < self.max_size {
            self.field_buffers.push(buf);
        }
    }
    
    fn get_ring_buffer(&mut self, size: usize, degree: usize) -> Vec<RingElement<F>> {
        if let Some(mut buf) = self.ring_buffers.pop() {
            buf.clear();
            buf.resize(size, RingElement {
                coeffs: vec![F::zero(); degree]
            });
            buf
        } else {
            vec![RingElement {
                coeffs: vec![F::zero(); degree]
            }; size]
        }
    }
    
    fn return_ring_buffer(&mut self, buf: Vec<RingElement<F>>) {
        if self.ring_buffers.len() < self.max_size {
            self.ring_buffers.push(buf);
        }
    }
}

// Streaming computation for large witnesses
struct StreamingComputation<F: Field> {
    chunk_size: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field> StreamingComputation<F> {
    fn new(chunk_size: usize) -> Self {
        Self {
            chunk_size,
            _phantom: PhantomData,
        }
    }
    
    // Process witness in chunks to reduce memory usage
    fn process_witness_chunked<T>(
        &self,
        witness: &[F],
        mut processor: impl FnMut(&[F]) -> T,
        mut combiner: impl FnMut(T, T) -> T,
        initial: T,
    ) -> T {
        let mut result = initial;
        
        for chunk in witness.chunks(self.chunk_size) {
            let chunk_result = processor(chunk);
            result = combiner(result, chunk_result);
        }
        
        result
    }
}
```

### 5. Parallel Processing

```rust
use rayon::prelude::*;

impl<F: Field + Send + Sync> NeoFoldingScheme<F> {
    // Parallel commitment computation
    fn commit_parallel(&self, witnesses: &[Vec<F>]) -> Result<Vec<VectorCommitment<F>>, Error> {
        witnesses.par_iter()
            .map(|witness| {
                let bit_widths = vec![F::MODULUS_BITS; witness.len()];
                self.commitment_scheme.commit_vector(witness, &bit_widths)
            })
            .collect()
    }
    
    // Parallel matrix-vector multiplications
    fn parallel_matrix_mul(
        matrices: &[SparseMatrix<F>],
        vector: &[F],
    ) -> Vec<Vec<F>> {
        matrices.par_iter()
            .map(|matrix| matrix.mul_vector(vector))
            .collect()
    }
    
    // Parallel MLE evaluations
    fn parallel_mle_eval(
        polynomials: &[MultilinearPolynomial<F>],
        point: &[F],
    ) -> Vec<F> {
        polynomials.par_iter()
            .map(|poly| poly.evaluate(point))
            .collect()
    }
}
```


## Security Analysis

### 1. Module-SIS Hardness

The security of Neo's commitment scheme relies on the Module-SIS assumption:

**Module-SIS(κ, n, q, β) Problem**: Given uniformly random matrix A ∈ R_q^{κ×n}, find non-zero vector z ∈ R_q^n with ||z||_∞ ≤ β such that Az = 0 mod q.

**Security Estimation**:

```rust
struct ModuleSISEstimator {
    kappa: usize,      // Module rank
    n: usize,          // Module dimension
    ring_degree: usize, // d
    modulus: u64,      // q
    norm_bound: u64,   // β
}

impl ModuleSISEstimator {
    // Estimate security level using lattice estimator
    fn estimate_security(&self) -> usize {
        // Lattice dimension: m = κ · d
        let lattice_dim = self.kappa * self.ring_degree;
        
        // Log of modulus
        let log_q = (self.modulus as f64).log2();
        
        // Hermite factor for BKZ
        // δ = ((π·β)^(1/m) · m / (2·π·e))^(1/(m-1))
        let m = lattice_dim as f64;
        let beta_f = self.norm_bound as f64;
        let delta = ((std::f64::consts::PI * beta_f).powf(1.0 / m) * m 
                    / (2.0 * std::f64::consts::PI * std::f64::consts::E))
                    .powf(1.0 / (m - 1.0));
        
        // BKZ block size: b ≈ log_δ(q) / log_δ(δ)
        let log_delta = delta.log2();
        let block_size = (log_q / log_delta) as usize;
        
        // Security level ≈ 0.292 · b (core-SVP hardness)
        let security = (0.292 * block_size as f64) as usize;
        
        security.min(256) // Cap at 256 bits
    }
    
    // Verify parameters provide target security
    fn verify_security(&self, target_bits: usize) -> bool {
        self.estimate_security() >= target_bits
    }
}
```

### 2. Soundness Analysis

**Sum-Check Soundness**: The sum-check protocol has soundness error ε_sc ≤ ℓ·d / |K| where:
- ℓ = number of variables
- d = polynomial degree
- K = challenge field (extension field for 128-bit security)

**Folding Soundness**: Each folding step has soundness error ε_fold ≤ d / |C| where:
- d = polynomial degree
- C = challenge set with |C| ≥ 2^128

**Total Soundness Error**:

```rust
struct SoundnessAnalyzer {
    num_variables: usize,      // ℓ
    polynomial_degree: usize,  // d
    extension_field_size: u128, // |K|
    challenge_set_size: u128,  // |C|
    num_folding_steps: usize,  // Number of folding operations
}

impl SoundnessAnalyzer {
    fn compute_total_error(&self) -> f64 {
        // Sum-check error
        let sumcheck_error = (self.num_variables * self.polynomial_degree) as f64 
                           / self.extension_field_size as f64;
        
        // Folding error (per step)
        let folding_error_per_step = self.polynomial_degree as f64 
                                    / self.challenge_set_size as f64;
        
        // Total folding error (union bound)
        let total_folding_error = folding_error_per_step * self.num_folding_steps as f64;
        
        // Total error (union bound)
        sumcheck_error + total_folding_error
    }
    
    fn verify_negligible(&self, target_bits: usize) -> bool {
        let error = self.compute_total_error();
        let threshold = 2.0_f64.powi(-(target_bits as i32));
        
        error < threshold
    }
    
    fn security_bits(&self) -> usize {
        let error = self.compute_total_error();
        if error <= 0.0 {
            return 256;
        }
        
        let bits = -(error.log2()) as usize;
        bits.min(256)
    }
}
```

### 3. Challenge Set Security

```rust
impl<F: Field> ChallengeSet<F> {
    // Verify challenge set provides sufficient security
    fn verify_security(&self, target_bits: usize) -> bool {
        // Check size: |C| ≥ 2^λ
        let size_bits = (self.elements.len() as f64).log2() as usize;
        if size_bits < target_bits {
            return false;
        }
        
        // Check norm bound
        if self.norm_bound > (F::MODULUS / 4) {
            return false;
        }
        
        // Check invertibility for sample pairs
        let sample_size = 100.min(self.elements.len());
        for i in 0..sample_size {
            for j in (i+1)..sample_size {
                if !self.check_invertibility(&self.elements[i], &self.elements[j]) {
                    return false;
                }
            }
        }
        
        true
    }
}
```


## Testing Strategy

### 1. Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    // Field arithmetic tests
    #[test]
    fn test_goldilocks_arithmetic() {
        let a = GoldilocksField::from_u64(12345);
        let b = GoldilocksField::from_u64(67890);
        
        // Test addition
        let sum = a.add(&b);
        assert_eq!(sum.to_canonical_u64(), 80235);
        
        // Test multiplication
        let prod = a.mul(&b);
        let expected = ((12345u128 * 67890u128) % GoldilocksField::MODULUS as u128) as u64;
        assert_eq!(prod.to_canonical_u64(), expected);
        
        // Test inversion
        let inv = a.inv().unwrap();
        let one = a.mul(&inv);
        assert_eq!(one.to_canonical_u64(), 1);
    }
    
    // Ring operation tests
    #[test]
    fn test_ring_multiplication() {
        let ring = CyclotomicRing::<GoldilocksField>::new_power_of_two(64);
        
        let a = RingElement {
            coeffs: vec![GoldilocksField::from_u64(1); 64]
        };
        let b = RingElement {
            coeffs: vec![GoldilocksField::from_u64(2); 64]
        };
        
        let prod = ring.mul(&a, &b);
        
        // Verify result
        assert_eq!(prod.coeffs.len(), 64);
    }
    
    // NTT tests
    #[test]
    fn test_ntt_correctness() {
        let ring = CyclotomicRing::<GoldilocksField>::new_power_of_two(64);
        
        let input: Vec<_> = (0..64)
            .map(|i| GoldilocksField::from_u64(i))
            .collect();
        
        let omega = ring.root_of_unity.unwrap();
        
        // Forward NTT
        let ntt_result = ring.ntt_forward(&input, omega);
        
        // Inverse NTT
        let recovered = ring.ntt_inverse(&ntt_result, omega);
        
        // Should recover original
        for (orig, rec) in input.iter().zip(recovered.iter()) {
            assert_eq!(orig.to_canonical_u64(), rec.to_canonical_u64());
        }
    }
    
    // Commitment tests
    #[test]
    fn test_commitment_binding() {
        let ring = CyclotomicRing::<GoldilocksField>::new_power_of_two(64);
        let scheme = AjtaiCommitmentScheme::setup(ring, 4, 10, 1 << 20);
        
        let witness1: Vec<_> = (0..10)
            .map(|i| RingElement {
                coeffs: vec![GoldilocksField::from_u64(i); 64]
            })
            .collect();
        
        let witness2: Vec<_> = (0..10)
            .map(|i| RingElement {
                coeffs: vec![GoldilocksField::from_u64(i + 1); 64]
            })
            .collect();
        
        let c1 = scheme.commit(&witness1).unwrap();
        let c2 = scheme.commit(&witness2).unwrap();
        
        // Different witnesses should give different commitments
        assert_ne!(c1.values, c2.values);
        
        // Verify opening
        assert!(scheme.verify_opening(&c1, &witness1).unwrap());
        assert!(!scheme.verify_opening(&c1, &witness2).unwrap());
    }
    
    // Multilinear polynomial tests
    #[test]
    fn test_mle_evaluation() {
        let evals = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let mle = MultilinearPolynomial::new(evals.clone());
        
        // Evaluate at Boolean points
        let point_00 = vec![GoldilocksField::zero(), GoldilocksField::zero()];
        assert_eq!(mle.evaluate(&point_00).to_canonical_u64(), 1);
        
        let point_11 = vec![GoldilocksField::one(), GoldilocksField::one()];
        assert_eq!(mle.evaluate(&point_11).to_canonical_u64(), 4);
    }
    
    // Decomposition tests
    #[test]
    fn test_witness_decomposition() {
        let decomp = WitnessDecomposition::<GoldilocksField>::new(1024);
        
        let witness = vec![
            GoldilocksField::from_u64(100),
            GoldilocksField::from_u64(500),
            GoldilocksField::from_u64(1000),
        ];
        
        let digits = decomp.decompose(&witness).unwrap();
        
        // Verify reconstruction
        let reconstructed = decomp.reconstruct(&digits);
        for (orig, rec) in witness.iter().zip(reconstructed.iter()) {
            assert_eq!(orig.to_canonical_u64(), rec.to_canonical_u64());
        }
        
        // Verify digit norms
        assert!(decomp.verify_digit_norms(&digits));
    }
}
```


### 2. Integration Tests

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[test]
    fn test_end_to_end_folding() {
        // Setup parameters
        let params = NeoParameters::goldilocks_128();
        params.validate().unwrap();
        
        // Create ring and folding scheme
        let ring = CyclotomicRing::<GoldilocksField>::new_power_of_two(params.ring_degree);
        let mut folding_scheme = NeoFoldingScheme::new(
            ring,
            params.commitment_dimension,
            params.norm_bound,
        );
        
        // Create simple CCS instances (e.g., R1CS)
        let structure = create_test_ccs_structure();
        
        let instance1 = CCSInstance {
            structure: structure.clone(),
            public_input: vec![GoldilocksField::from_u64(1)],
        };
        
        let witness1 = CCSWitness {
            private_witness: vec![GoldilocksField::from_u64(2)],
        };
        
        let instance2 = CCSInstance {
            structure: structure.clone(),
            public_input: vec![GoldilocksField::from_u64(3)],
        };
        
        let witness2 = CCSWitness {
            private_witness: vec![GoldilocksField::from_u64(4)],
        };
        
        // Verify instances are valid
        assert!(instance1.verify(&witness1));
        assert!(instance2.verify(&witness2));
        
        // Fold instances
        let mut transcript = Transcript::new(b"test_folding");
        let (folded_claim, folded_witness) = folding_scheme.fold(
            &instance1,
            &witness1,
            &instance2,
            &witness2,
            &mut transcript,
        ).unwrap();
        
        // Verify folded claim
        assert!(folded_claim.verify(&folded_witness));
    }
    
    #[test]
    fn test_ivc_multiple_steps() {
        let params = NeoParameters::goldilocks_128();
        let ring = CyclotomicRing::<GoldilocksField>::new_power_of_two(params.ring_degree);
        let folding_scheme = NeoFoldingScheme::new(
            ring,
            params.commitment_dimension,
            params.norm_bound,
        );
        
        let step_circuit = create_test_ccs_structure();
        let mut ivc_scheme = IVCScheme::new(folding_scheme, step_circuit);
        
        // Initialize IVC
        let initial_state = vec![GoldilocksField::from_u64(0)];
        let initial_witness = CCSWitness {
            private_witness: vec![GoldilocksField::from_u64(1)],
        };
        
        let mut transcript = Transcript::new(b"test_ivc");
        let mut proof = ivc_scheme.init(&initial_state, &initial_witness, &mut transcript).unwrap();
        
        // Prove multiple steps
        for i in 1..=5 {
            let next_state = vec![GoldilocksField::from_u64(i)];
            let step_witness = CCSWitness {
                private_witness: vec![GoldilocksField::from_u64(i + 1)],
            };
            
            proof = ivc_scheme.prove_step(
                &proof,
                &next_state,
                &step_witness,
                &mut transcript,
            ).unwrap();
        }
        
        // Verify final proof
        let final_state = vec![GoldilocksField::from_u64(5)];
        let is_valid = ivc_scheme.verify(
            &proof,
            &initial_state,
            &final_state,
            &mut transcript,
        ).unwrap();
        
        assert!(is_valid);
        assert_eq!(proof.step_count, 6); // Initial + 5 steps
    }
    
    fn create_test_ccs_structure() -> CCSStructure<GoldilocksField> {
        // Create simple R1CS: (1 + x) * (2 + w) = 6
        // Matrices: A, B, C
        // Az = [1 + x], Bz = [2 + w], Cz = [6]
        
        let m = 1; // 1 constraint
        let n = 4; // z = (1, x, w, 6)
        let n_padded = 4;
        let ell = 2;
        let t = 3; // 3 matrices
        let q = 1; // 1 term
        let d = 2; // degree 2
        
        // Matrix A: [1, 1, 0, 0]
        let matrix_a = SparseMatrix {
            rows: 1,
            cols: 4,
            entries: vec![
                (0, 0, GoldilocksField::one()),
                (0, 1, GoldilocksField::one()),
            ],
        };
        
        // Matrix B: [2, 0, 1, 0]
        let matrix_b = SparseMatrix {
            rows: 1,
            cols: 4,
            entries: vec![
                (0, 0, GoldilocksField::from_u64(2)),
                (0, 2, GoldilocksField::one()),
            ],
        };
        
        // Matrix C: [0, 0, 0, 1]
        let matrix_c = SparseMatrix {
            rows: 1,
            cols: 4,
            entries: vec![
                (0, 3, GoldilocksField::one()),
            ],
        };
        
        CCSStructure {
            m,
            n,
            n_padded,
            ell,
            t,
            q,
            d,
            matrices: vec![matrix_a, matrix_b, matrix_c],
            selectors: vec![vec![0, 1]], // A ∘ B
            constants: vec![GoldilocksField::one()],
        }
    }
}
```


### 3. Property-Based Tests

```rust
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    
    proptest! {
        #[test]
        fn test_field_arithmetic_properties(a in 0u64..GoldilocksField::MODULUS, 
                                            b in 0u64..GoldilocksField::MODULUS) {
            let fa = GoldilocksField::from_u64(a);
            let fb = GoldilocksField::from_u64(b);
            
            // Commutativity
            assert_eq!(fa.add(&fb), fb.add(&fa));
            assert_eq!(fa.mul(&fb), fb.mul(&fa));
            
            // Associativity
            let fc = GoldilocksField::from_u64((a + b) % GoldilocksField::MODULUS);
            assert_eq!(fa.add(&fb).add(&fc), fa.add(&fb.add(&fc)));
            
            // Distributivity
            let sum = fb.add(&fc);
            assert_eq!(fa.mul(&sum), fa.mul(&fb).add(&fa.mul(&fc)));
        }
        
        #[test]
        fn test_commitment_homomorphism(
            w1 in prop::collection::vec(0u64..1000, 10),
            w2 in prop::collection::vec(0u64..1000, 10),
            alpha in 1u64..100,
            beta in 1u64..100,
        ) {
            let ring = CyclotomicRing::<GoldilocksField>::new_power_of_two(64);
            let scheme = AjtaiCommitmentScheme::setup(ring.clone(), 4, 10, 1 << 20);
            
            // Convert to ring elements
            let witness1: Vec<_> = w1.iter()
                .map(|&x| RingElement {
                    coeffs: vec![GoldilocksField::from_u64(x); 64]
                })
                .collect();
            
            let witness2: Vec<_> = w2.iter()
                .map(|&x| RingElement {
                    coeffs: vec![GoldilocksField::from_u64(x); 64]
                })
                .collect();
            
            // Commit separately
            let c1 = scheme.commit(&witness1).unwrap();
            let c2 = scheme.commit(&witness2).unwrap();
            
            // Linear combination of commitments
            let alpha_ring = RingElement {
                coeffs: vec![GoldilocksField::from_u64(alpha); 64]
            };
            let beta_ring = RingElement {
                coeffs: vec![GoldilocksField::from_u64(beta); 64]
            };
            
            let c_combined = Commitment::linear_combination(
                &[c1, c2],
                &[alpha_ring.clone(), beta_ring.clone()],
            );
            
            // Linear combination of witnesses
            let mut w_combined = Vec::new();
            for i in 0..10 {
                let term1 = ring.mul(&alpha_ring, &witness1[i]);
                let term2 = ring.mul(&beta_ring, &witness2[i]);
                w_combined.push(ring.add(&term1, &term2));
            }
            
            // Verify homomorphism
            let c_direct = scheme.commit(&w_combined).unwrap();
            assert_eq!(c_combined.values, c_direct.values);
        }
        
        #[test]
        fn test_decomposition_reconstruction(
            values in prop::collection::vec(0u64..1024, 20)
        ) {
            let decomp = WitnessDecomposition::<GoldilocksField>::new(1024);
            
            let witness: Vec<_> = values.iter()
                .map(|&x| GoldilocksField::from_u64(x))
                .collect();
            
            let digits = decomp.decompose(&witness).unwrap();
            let reconstructed = decomp.reconstruct(&digits);
            
            for (orig, rec) in witness.iter().zip(reconstructed.iter()) {
                assert_eq!(orig.to_canonical_u64(), rec.to_canonical_u64());
            }
            
            assert!(decomp.verify_digit_norms(&digits));
        }
    }
}
```

### 4. Benchmark Tests

```rust
#[cfg(test)]
mod benchmarks {
    use super::*;
    use std::time::Instant;
    
    #[test]
    fn benchmark_field_operations() {
        const N: usize = 1_000_000;
        
        let a = GoldilocksField::from_u64(12345);
        let b = GoldilocksField::from_u64(67890);
        
        // Addition
        let start = Instant::now();
        for _ in 0..N {
            let _ = a.add(&b);
        }
        let add_time = start.elapsed();
        println!("Addition: {} ns/op", add_time.as_nanos() / N as u128);
        
        // Multiplication
        let start = Instant::now();
        for _ in 0..N {
            let _ = a.mul(&b);
        }
        let mul_time = start.elapsed();
        println!("Multiplication: {} ns/op", mul_time.as_nanos() / N as u128);
        
        // Inversion
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = a.inv();
        }
        let inv_time = start.elapsed();
        println!("Inversion: {} ns/op", inv_time.as_nanos() / 1000);
    }
    
    #[test]
    fn benchmark_ntt() {
        let ring = CyclotomicRing::<GoldilocksField>::new_power_of_two(64);
        let omega = ring.root_of_unity.unwrap();
        
        let input: Vec<_> = (0..64)
            .map(|i| GoldilocksField::from_u64(i))
            .collect();
        
        const ITERATIONS: usize = 10000;
        
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _ = ring.ntt_forward(&input, omega);
        }
        let ntt_time = start.elapsed();
        println!("NTT (64): {} μs/op", ntt_time.as_micros() / ITERATIONS as u128);
    }
    
    #[test]
    fn benchmark_commitment() {
        let ring = CyclotomicRing::<GoldilocksField>::new_power_of_two(64);
        let scheme = AjtaiCommitmentScheme::setup(ring, 4, 256, 1 << 20);
        
        let witness: Vec<_> = (0..256)
            .map(|i| RingElement {
                coeffs: vec![GoldilocksField::from_u64(i); 64]
            })
            .collect();
        
        const ITERATIONS: usize = 100;
        
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _ = scheme.commit(&witness).unwrap();
        }
        let commit_time = start.elapsed();
        println!("Commitment (256 ring elems): {} ms/op", 
                 commit_time.as_millis() / ITERATIONS as u128);
    }
    
    #[test]
    fn benchmark_folding() {
        let params = NeoParameters::goldilocks_128();
        let ring = CyclotomicRing::<GoldilocksField>::new_power_of_two(params.ring_degree);
        let mut folding_scheme = NeoFoldingScheme::new(
            ring,
            params.commitment_dimension,
            params.norm_bound,
        );
        
        let structure = create_test_ccs_structure();
        let instance1 = CCSInstance {
            structure: structure.clone(),
            public_input: vec![GoldilocksField::from_u64(1)],
        };
        let witness1 = CCSWitness {
            private_witness: vec![GoldilocksField::from_u64(2)],
        };
        let instance2 = CCSInstance {
            structure: structure.clone(),
            public_input: vec![GoldilocksField::from_u64(3)],
        };
        let witness2 = CCSWitness {
            private_witness: vec![GoldilocksField::from_u64(4)],
        };
        
        let start = Instant::now();
        let mut transcript = Transcript::new(b"benchmark");
        let _ = folding_scheme.fold(
            &instance1,
            &witness1,
            &instance2,
            &witness2,
            &mut transcript,
        ).unwrap();
        let fold_time = start.elapsed();
        
        println!("Folding: {} ms", fold_time.as_millis());
    }
}
```


## Implementation Roadmap

### Phase 1: Core Primitives (Weeks 1-3)

**Week 1: Field Arithmetic**
- Implement Goldilocks field with optimized arithmetic
- Implement Mersenne 61 field with fast reduction
- Implement extension field F_q^2
- Add SIMD optimizations for batch operations
- Unit tests for all field operations

**Week 2: Ring Operations**
- Implement cyclotomic ring structure
- Implement NTT-based polynomial multiplication
- Implement coefficient embedding/extraction
- Implement rotation matrices
- Unit tests for ring operations

**Week 3: Multilinear Polynomials**
- Implement multilinear polynomial representation
- Implement efficient MLE evaluation
- Implement partial evaluation
- Implement equality polynomial
- Unit tests for polynomial operations

### Phase 2: Commitment Scheme (Weeks 4-6)

**Week 4: Ajtai Commitments**
- Implement basic Ajtai commitment scheme
- Implement commitment verification
- Implement linear homomorphism
- Unit tests for commitment binding

**Week 5: Matrix Commitments**
- Implement field vector to ring vector packing
- Implement pay-per-bit cost tracking
- Implement unpacking operations
- Unit tests for packing/unpacking

**Week 6: Evaluation Claims**
- Implement evaluation claim structure
- Implement claim folding
- Implement cross-term computation
- Integration tests for commitment + folding

### Phase 3: CCS and Sum-Check (Weeks 7-9)

**Week 7: CCS Structure**
- Implement CCS structure definition
- Implement sparse matrix operations
- Implement CCS verification
- Unit tests for CCS operations

**Week 8: Sum-Check Protocol**
- Implement sum-check prover
- Implement sum-check verifier
- Implement transcript management
- Unit tests for sum-check

**Week 9: CCS Reduction**
- Implement CCS to evaluation claims reduction
- Implement matrix-vector MLE reduction
- Integration tests for full reduction

### Phase 4: Folding Scheme (Weeks 10-12)

**Week 10: Decomposition**
- Implement witness decomposition
- Implement digit reconstruction
- Implement norm verification
- Unit tests for decomposition

**Week 11: RLC and Challenge Sets**
- Implement challenge set generation
- Implement RLC reduction
- Implement invertibility checks
- Unit tests for RLC

**Week 12: Complete Folding**
- Integrate all reductions
- Implement complete folding protocol
- Implement folding verification
- Integration tests for end-to-end folding

### Phase 5: IVC/PCD (Weeks 13-15)

**Week 13: IVC Construction**
- Implement IVC initialization
- Implement step proving
- Implement IVC verification
- Unit tests for IVC

**Week 14: Proof Compression**
- Implement SNARK integration (Spartan + FRI)
- Implement proof compression
- Implement compressed verification
- Integration tests for compression

**Week 15: Optimization and Polish**
- Profile and optimize hot paths
- Add parallel processing
- Optimize memory usage
- Performance benchmarks

### Phase 6: Testing and Documentation (Weeks 16-18)

**Week 16: Comprehensive Testing**
- Property-based tests
- Fuzzing tests
- Security tests
- Edge case tests

**Week 17: Documentation**
- API documentation
- Usage examples
- Security considerations
- Performance guidelines

**Week 18: Final Integration**
- End-to-end examples
- Benchmark suite
- Security audit preparation
- Release preparation


## Concrete Examples

### Example 1: Simple R1CS Folding

```rust
fn example_r1cs_folding() -> Result<(), Error> {
    // Setup: Prove (1 + x) * (2 + w) = 6
    // where x = 1 (public), w = 1 (private)
    
    // Initialize parameters
    let params = NeoParameters::goldilocks_128();
    let ring = CyclotomicRing::<GoldilocksField>::new_power_of_two(64);
    let mut folding_scheme = NeoFoldingScheme::new(
        ring,
        params.commitment_dimension,
        params.norm_bound,
    );
    
    // Create R1CS structure
    // Variables: z = (1, x, w, out) = (1, 1, 1, 6)
    let structure = CCSStructure {
        m: 1,
        n: 4,
        n_padded: 4,
        ell: 2,
        t: 3,
        q: 1,
        d: 2,
        matrices: vec![
            // A: [1, 1, 0, 0] -> Az = 1 + x = 2
            SparseMatrix {
                rows: 1,
                cols: 4,
                entries: vec![
                    (0, 0, GoldilocksField::one()),
                    (0, 1, GoldilocksField::one()),
                ],
            },
            // B: [2, 0, 1, 0] -> Bz = 2 + w = 3
            SparseMatrix {
                rows: 1,
                cols: 4,
                entries: vec![
                    (0, 0, GoldilocksField::from_u64(2)),
                    (0, 2, GoldilocksField::one()),
                ],
            },
            // C: [0, 0, 0, 1] -> Cz = out = 6
            SparseMatrix {
                rows: 1,
                cols: 4,
                entries: vec![
                    (0, 3, GoldilocksField::one()),
                ],
            },
        ],
        selectors: vec![vec![0, 1]], // A ∘ B - C = 0
        constants: vec![GoldilocksField::one()],
    };
    
    // First instance: x = 1, w = 1, out = 6
    let instance1 = CCSInstance {
        structure: structure.clone(),
        public_input: vec![GoldilocksField::one()],
    };
    let witness1 = CCSWitness {
        private_witness: vec![
            GoldilocksField::one(),
            GoldilocksField::from_u64(6),
        ],
    };
    
    // Verify first instance
    assert!(instance1.verify(&witness1));
    println!("Instance 1 verified: (1 + 1) * (2 + 1) = 6");
    
    // Second instance: x = 2, w = 2, out = 12
    let instance2 = CCSInstance {
        structure: structure.clone(),
        public_input: vec![GoldilocksField::from_u64(2)],
    };
    let witness2 = CCSWitness {
        private_witness: vec![
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(12),
        ],
    };
    
    // Verify second instance
    assert!(instance2.verify(&witness2));
    println!("Instance 2 verified: (1 + 2) * (2 + 2) = 12");
    
    // Fold the two instances
    let mut transcript = Transcript::new(b"r1cs_folding_example");
    let (folded_claim, folded_witness) = folding_scheme.fold(
        &instance1,
        &witness1,
        &instance2,
        &witness2,
        &mut transcript,
    )?;
    
    println!("Folding successful!");
    println!("Folded claim point: {:?}", folded_claim.point);
    println!("Folded claim value: {}", folded_claim.value.to_canonical_u64());
    
    // Verify folded claim
    assert!(folded_claim.verify(&folded_witness));
    println!("Folded claim verified!");
    
    Ok(())
}
```

### Example 2: IVC for Fibonacci Sequence

```rust
fn example_fibonacci_ivc() -> Result<(), Error> {
    // Prove Fibonacci sequence: F(n+1) = F(n) + F(n-1)
    // Starting with F(0) = 0, F(1) = 1
    
    let params = NeoParameters::goldilocks_128();
    let ring = CyclotomicRing::<GoldilocksField>::new_power_of_two(64);
    let folding_scheme = NeoFoldingScheme::new(
        ring,
        params.commitment_dimension,
        params.norm_bound,
    );
    
    // Create CCS for Fibonacci step: out = a + b
    let fib_structure = CCSStructure {
        m: 1,
        n: 4,
        n_padded: 4,
        ell: 2,
        t: 2,
        q: 1,
        d: 1,
        matrices: vec![
            // A: [0, 1, 1, 0] -> Az = a + b
            SparseMatrix {
                rows: 1,
                cols: 4,
                entries: vec![
                    (0, 1, GoldilocksField::one()),
                    (0, 2, GoldilocksField::one()),
                ],
            },
            // B: [0, 0, 0, 1] -> Bz = out
            SparseMatrix {
                rows: 1,
                cols: 4,
                entries: vec![
                    (0, 3, GoldilocksField::one()),
                ],
            },
        ],
        selectors: vec![vec![0]], // A - B = 0
        constants: vec![GoldilocksField::one()],
    };
    
    let mut ivc_scheme = IVCScheme::new(folding_scheme, fib_structure);
    
    // Initialize with F(0) = 0, F(1) = 1
    let initial_state = vec![
        GoldilocksField::zero(),  // F(0)
        GoldilocksField::one(),   // F(1)
    ];
    let initial_witness = CCSWitness {
        private_witness: vec![GoldilocksField::one()], // F(2) = 1
    };
    
    let mut transcript = Transcript::new(b"fibonacci_ivc");
    let mut proof = ivc_scheme.init(&initial_state, &initial_witness, &mut transcript)?;
    
    println!("IVC initialized: F(0) = 0, F(1) = 1, F(2) = 1");
    
    // Compute next 10 Fibonacci numbers
    let mut fib_prev = 1u64;
    let mut fib_curr = 1u64;
    
    for i in 3..=12 {
        let fib_next = fib_prev + fib_curr;
        
        let next_state = vec![
            GoldilocksField::from_u64(fib_curr),
            GoldilocksField::from_u64(fib_next),
        ];
        
        let step_witness = CCSWitness {
            private_witness: vec![GoldilocksField::from_u64(fib_next)],
        };
        
        proof = ivc_scheme.prove_step(
            &proof,
            &next_state,
            &step_witness,
            &mut transcript,
        )?;
        
        println!("Step {}: F({}) = {}", i - 2, i, fib_next);
        
        fib_prev = fib_curr;
        fib_curr = fib_next;
    }
    
    // Verify final proof
    let final_state = vec![
        GoldilocksField::from_u64(fib_prev),
        GoldilocksField::from_u64(fib_curr),
    ];
    
    let is_valid = ivc_scheme.verify(
        &proof,
        &initial_state,
        &final_state,
        &mut transcript,
    )?;
    
    assert!(is_valid);
    println!("IVC proof verified! Computed {} Fibonacci steps", proof.step_count);
    
    Ok(())
}
```

### Example 3: Pay-Per-Bit Commitment

```rust
fn example_pay_per_bit() -> Result<(), Error> {
    let ring = CyclotomicRing::<GoldilocksField>::new_power_of_two(64);
    let mut scheme = MatrixCommitmentScheme::new(ring, 4, 1 << 20);
    
    // Example 1: Commit to bits (1-bit values)
    let bits = vec![
        GoldilocksField::zero(),
        GoldilocksField::one(),
        GoldilocksField::one(),
        GoldilocksField::zero(),
    ];
    let bit_widths_1 = vec![1; bits.len()];
    
    let cost_bits = scheme.commitment_cost(bits.len(), &bit_widths_1);
    println!("Cost for {} bits: {} ring multiplications", bits.len(), cost_bits);
    
    // Example 2: Commit to 32-bit values
    let values_32 = vec![
        GoldilocksField::from_u64(12345),
        GoldilocksField::from_u64(67890),
        GoldilocksField::from_u64(11111),
        GoldilocksField::from_u64(22222),
    ];
    let bit_widths_32 = vec![32; values_32.len()];
    
    let cost_32bit = scheme.commitment_cost(values_32.len(), &bit_widths_32);
    println!("Cost for {} 32-bit values: {} ring multiplications", 
             values_32.len(), cost_32bit);
    
    // Example 3: Commit to 64-bit values
    let values_64 = vec![
        GoldilocksField::from_u64(1 << 50),
        GoldilocksField::from_u64(1 << 51),
        GoldilocksField::from_u64(1 << 52),
        GoldilocksField::from_u64(1 << 53),
    ];
    let bit_widths_64 = vec![64; values_64.len()];
    
    let cost_64bit = scheme.commitment_cost(values_64.len(), &bit_widths_64);
    println!("Cost for {} 64-bit values: {} ring multiplications", 
             values_64.len(), cost_64bit);
    
    // Show pay-per-bit advantage
    let speedup_32 = cost_64bit as f64 / cost_32bit as f64;
    let speedup_1 = cost_64bit as f64 / cost_bits as f64;
    
    println!("\nPay-per-bit advantage:");
    println!("  32-bit vs 64-bit: {:.1}x faster", speedup_32);
    println!("  1-bit vs 64-bit: {:.1}x faster", speedup_1);
    
    Ok(())
}
```


## Conclusion

This design document provides a comprehensive blueprint for implementing Neo, a lattice-based folding scheme for CCS with the following key features:

### Key Achievements

1. **Post-Quantum Security**: Based on Module-SIS hardness assumption, providing plausible post-quantum security unlike elliptic curve-based schemes.

2. **Pay-Per-Bit Commitments**: Novel commitment scheme where costs scale linearly with bit-width, achieving up to 64x speedup for small values compared to full field elements.

3. **Small Field Support**: Native support for efficient fields like Goldilocks (2^64 - 2^32 + 1) and Mersenne 61 (2^61 - 1), enabling fast arithmetic without "wrong field" emulation.

4. **Efficient Folding**: Single sum-check invocation over extension fields instead of cyclotomic rings, reducing overhead compared to prior lattice-based schemes.

5. **Modular Architecture**: Clean separation of concerns with well-defined interfaces between layers, enabling independent optimization and testing.

### Performance Characteristics

**Prover Complexity**:
- Dominated by O(N) commitment operations where N is witness size
- NTT-based polynomial multiplication: O(d log d) per ring operation
- Sum-check: O(N · d) field operations
- Pay-per-bit advantage: Up to 64x faster for small values

**Verifier Complexity**:
- O(log N) for sum-check verification
- O(κ) for commitment operations where κ is commitment dimension
- Much faster than traditional SNARK verification

**Proof Size**:
- O(log N) field elements for sum-check
- O(κ · d) for commitments
- Can be compressed to O(1) using final SNARK

### Security Guarantees

**128-bit Security Parameters** (Goldilocks):
- Ring degree: d = 64
- Commitment dimension: κ = 4
- Norm bound: β = 2^20
- Challenge set size: |C| ≥ 2^128
- Module-SIS hardness: ≈ 128 bits

**Soundness Error**:
- Sum-check: ε_sc ≤ ℓ·d / |F_q^2|
- Folding: ε_fold ≤ d / |C|
- Total: ε_total ≤ 2^(-128) with proper parameters

### Implementation Considerations

1. **Optimization Priorities**:
   - NTT implementation (most critical for performance)
   - SIMD vectorization for field operations
   - Sparse matrix operations
   - Memory pooling for temporary allocations

2. **Testing Strategy**:
   - Comprehensive unit tests for all components
   - Property-based tests for algebraic properties
   - Integration tests for end-to-end workflows
   - Benchmark suite for performance tracking

3. **Future Extensions**:
   - Lookup argument integration (Shout/Twist)
   - Read-write memory support
   - Additional field choices
   - Hardware acceleration (GPU/FPGA)

### Comparison with Prior Work

**vs HyperNova**:
- ✓ Post-quantum security
- ✓ Small field support
- ✓ No elliptic curve cycles needed
- ≈ Similar prover complexity
- ≈ Similar verifier complexity

**vs LatticeFold**:
- ✓ Pay-per-bit commitments
- ✓ Single sum-check over extension field
- ✓ Support for Goldilocks/M61
- ✓ No packing overhead
- ✓ Simpler protocol structure

**vs Arc/Lova**:
- ✓ Much smaller verifier circuit
- ✓ Much faster prover
- ✓ Standard CCS support
- ✓ Practical performance

This design provides a solid foundation for a production-ready implementation of Neo that achieves the goals of post-quantum security, efficiency, and practical usability.

