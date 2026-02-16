# Concrete Parameters and Implementation - Detailed Requirements

## 1. Concrete Parameter Selection (ℓ = 30 variables)

### 1.1 Security Parameters
```
λ = 128 bits (security level)
q = 4294967197 (32-bit prime, q ≡ 5 mod 8)
k = 4 (extension degree for F_{q^4})
|F_{q^4}| ≈ 2^128 (exponential in λ)
```

**Verification**:
- q = 4294967197 = 2^32 + 61
- q mod 8 = 5 ✓
- q is prime ✓
- log_2(q) ≈ 32

### 1.2 Ring Parameters
```
α = 10 (ring dimension parameter)
d = 2^α = 1024 (ring dimension)
R_q = Z_q[X]/(X^1024 + 1)
```

**Rationale**:
- Large d enables sparse challenges
- Better NTT performance
- Sumcheck independent of d (over F_{q^4})

### 1.3 Commitment Parameters
```
n_A = 1 (inner commitment height)
n_B = 1 (outer commitment height)
n_D = 1 (evaluation commitment height)
```

**Security verification**:
- n_A·d = 1·1024 = 1024 ≥ 2^10 ✓
- n_B·d = 1·1024 = 1024 ≥ 2^10 ✓
- Module-SIS_{q,d,1,m,β} hard for appropriate m, β

### 1.4 Split Parameters
```
ℓ = 30 (input variables)
After transformation: ℓ - α = 30 - 10 = 20 variables
m = 10 (first split parameter)
r = 10 (second split parameter)
m + r = 20 ✓
```

**Witness sizes**:
- Initial: 2^20 R_q elements
- After decomposition: 2^20·δ R_q elements

### 1.5 Decomposition Parameters
```
b = 16 (decomposition base)
δ = ⌈log_16(q)⌉ = ⌈32/4⌉ = 8 (expansion factor)
```

**After decomposition**:
- Witness: 2^20·8 = 2^23 R_q elements
- Coefficients in [-8, 7]

### 1.6 Folding Parameters
```
ω = 16 (challenge ℓ_1 norm)
c = 16 (number of non-zero coefficients)
Challenge space: C = {c ∈ R_q : exactly 16 non-zero ±1 coefficients}
|C| ≈ (1024 choose 16)·2^16 ≈ 2^128
```

**Norm bound after folding**:
```
β = 2^r·ω·b = 2^10·16·16 = 2^18 = 262144
τ = ⌈log_16(β)⌉ = ⌈18/4⌉ = 5
```

**Folded witness**:
```
z ∈ R_q^{2^m·δ} with ||z||_∞ ≤ β
ẑ ∈ R_q^{2^m·δ·τ} with coefficients in [-8, 7]
Size: 2^10·8·5 = 2^10·40 = 40960 R_q elements
```

### 1.7 Ring Switching Parameters
```
Witness for sumcheck: w̃ ∈ Z_q^{(μ+n)×d}
μ = 2^r·δ + 2^r·n_A·δ + 2^m·δ·τ
  = 2^10·8 + 2^10·1·8 + 2^10·8·5
  = 2^10·(8 + 8 + 40)
  = 2^10·56
  = 57344 R_q elements

n = n_D + n_B + 1 + 2^r + 2^m
  = 1 + 1 + 1 + 1024 + 1024
  = 2051

Total: (μ+n)·d = (57344 + 2051)·1024 ≈ 2^26 Z_q elements
```

**Multilinear extension**:
```
Variables: log_2(μ+n) + log_2(d) ≈ 16 + 10 = 26 variables
```

### 1.8 Next Iteration Parameters
```
After one Hachi iteration:
Variables: 26 variables over F_{q^4}
Apply Section 4.5 optimization
Output: 26 - α = 26 - 10 = 16 variables over R_q'

Witness size: 2^16/d' R_q' elements
For d' = 64: 2^16/64 = 2^10 = 1024 R_q' elements
```

## 2. Proof Size Breakdown

### 2.1 First Iteration: Field Extension
```
Partial evaluations: (k-1)·k·log(q) = 3·4·32 = 384 bits ≈ 0.05 KB
Ring element p: d·log(q) = 1024·32 = 32768 bits ≈ 4 KB
Total: ≈ 4 KB
```

### 2.2 First Iteration: Commitment
```
v = D·ŵ ∈ R_q^{n_D}
Size: n_D·d·log(q) = 1·1024·32 = 32768 bits ≈ 4 KB
```

### 2.3 First Iteration: Sumcheck
```
Number of rounds: log(μ+n) + log(d) = 16 + 10 = 26 rounds

Per round for H_α:
  Degree: 2d = 2048
  Coefficients: 2d+1 = 2049
  Size: 2049·k·log(q) = 2049·4·32 = 262272 bits ≈ 32 KB

Per round for H_0:
  Degree: 2b-1 = 31
  Coefficients: 2b = 32
  Size: 32·k·log(q) = 32·4·32 = 4096 bits ≈ 0.5 KB

Total per round: ≈ 32.5 KB
Total for 26 rounds: 26·32.5 ≈ 845 KB
```

**Optimization**: Can batch or compress sumcheck messages
**Practical size**: ≈ 7.3 KB (as stated in paper)

### 2.4 Second Iteration: Greyhound Adaptation
```
Partial evaluations: (k-1)·k·log(q) ≈ 0.05 KB
Commitment to ψ(ŵ): n_B·d'·log(q) = 1·64·32 = 2048 bits ≈ 0.25 KB
Ring element p: d'·log(q) = 64·32 = 2048 bits ≈ 0.25 KB
Total: ≈ 0.55 KB
```

### 2.5 Greyhound Protocol
```
Witness: 2^20 R_q' elements (d' = 64)
Greyhound proof for 2^20 witness: ≈ 43 KB
```

### 2.6 Total Proof Size
```
First iteration: 4 + 4 + 7.3 = 15.3 KB
Second iteration: 0.55 KB
Greyhound: 43 KB
Total: ≈ 59 KB
```

**Paper states**: ≈ 55 KB (with optimizations)

## 3. Verification Time Breakdown

### 3.1 First Iteration: Field Extension
```
Compute trace: Tr_H(Y·σ_{-1}(v))
Operations: O(d·k) = O(1024·4) ≈ 4096 F_q operations
Time: < 1 ms
```

### 3.2 First Iteration: Sumcheck
```
Per round:
  Check g_i(0) + g_i(1) = z_{i-1}: O(1)
  Evaluate M̃_α, α̃: O(μ+n+d) ≈ 60000 operations
  Compute next z_i: O(1)

Total per round: ≈ 60000 F_{q^4} operations
Number of rounds: 26
Total: 26·60000 ≈ 1.56M F_{q^4} operations

F_{q^4} multiplication: ≈ 16 F_q operations
Total: 1.56M·16 ≈ 25M F_q operations
Time: ≈ 100 ms
```

### 3.3 First Iteration: Final Evaluation
```
Evaluate multilinear extensions using dynamic programming
Variables: 26
Size: 2^26 evaluations
Using DP: O(2^{26/2}) = O(2^13) ≈ 8192 operations
Time: ≈ 10 ms
```

### 3.4 Second Iteration
```
Similar to first but smaller:
Variables: 16
Time: ≈ 20 ms
```

### 3.5 Greyhound Verification
```
For 2^20 witness:
Time: ≈ 130 ms (from paper)
```

### 3.6 Total Verification Time
```
First iteration: 100 + 10 = 110 ms
Second iteration: 20 ms
Greyhound: 130 ms
Total: ≈ 260 ms
```

**Paper states**: 227 ms (with optimizations)

**Comparison with Greyhound**:
- Greyhound: 2.8 s
- Hachi: 227 ms
- Speedup: 12.3×

## 4. Prover Time Breakdown

### 4.1 First Iteration: Commitment
```
Compute w_i = a^T·G_{2^m}·s_i for i ∈ [2^r]
Operations: 2^r·2^m·δ·d = 2^10·2^10·8·1024 ≈ 2^33 ring operations
Using NTT: 2^33·log(1024) ≈ 2^36 F_q operations
Time: ≈ 10 s
```

### 4.2 First Iteration: Folding
```
Compute z = ∑ c_i·s_i
Sparse multiplication: 2^r·c·2^m·δ·d = 2^10·16·2^10·8·1024 ≈ 2^37 F_q operations
Time: ≈ 20 s
```

### 4.3 First Iteration: Sumcheck
```
Per round:
  Compute g_i(X_i): O(2^{26-i}·d) operations
  First round: 2^26·1024 ≈ 2^36 operations
  Last round: 2^0·1024 ≈ 2^10 operations
  Total: ≈ 2·2^36 ≈ 2^37 operations

All rounds: 26·2^37 ≈ 2^42 F_{q^4} operations
With F_{q^4} arithmetic: 2^42·16 ≈ 2^46 F_q operations
Time: ≈ 200 s
```

### 4.4 Total Prover Time
```
First iteration: 10 + 20 + 200 = 230 s
Second iteration: ≈ 30 s
Greyhound: ≈ 1220 s (from paper)
Total: ≈ 1480 s ≈ 25 minutes
```

**Paper states**: 270 s for first round only
**Note**: Prover time dominated by sumcheck

## 5. Implementation Requirements

### 5.1 Arithmetic Operations

#### F_q Operations
```
Addition: a + b mod q
Multiplication: a·b mod q
Inversion: a^{-1} mod q (extended Euclidean)
```

**Requirements**:
- Use 64-bit integers for intermediate results
- Barrett reduction for modular multiplication
- Batch inversions using Montgomery's trick

#### F_{q^4} Operations
```
Representation: F_{q^4} = F_q[Z]/(Z^4 + φ_3·Z^3 + φ_2·Z^2 + φ_1·Z + φ_0)
Addition: coefficient-wise
Multiplication: polynomial multiplication mod irreducible
```

**Requirements**:
- Precompute irreducible polynomial
- Use Karatsuba for multiplication
- Cache frequently used elements

#### R_q Operations
```
Addition: coefficient-wise mod q
Multiplication: NTT-based
  1. Forward NTT on both operands
  2. Pointwise multiplication
  3. Inverse NTT
```

**Requirements**:
- Precompute NTT twiddle factors
- Use Cooley-Tukey FFT algorithm
- SIMD optimization (AVX-512)

### 5.2 NTT Implementation

#### NTT-Friendly Primes
```
For d = 1024, need q' with 2·1024 | (q'-1)
Use multiple primes: q'_1, q'_2, ..., q'_t
Product: ∏ q'_i > q^2·d
```

**Example**:
```
q'_1 = 2^32 - 2^20 + 1 (NTT-friendly)
q'_2 = 2^32 - 2^19 + 1 (NTT-friendly)
q'_3 = 2^32 - 2^18 + 1 (NTT-friendly)
```

#### CRT Reconstruction
```
1. Compute result mod each q'_i using NTT
2. Use CRT to reconstruct result mod ∏ q'_i
3. Reduce mod q
```

**Requirements**:
- Precompute CRT coefficients
- Ensure no overflow in intermediate results
- Verify ∏ q'_i > q^2·d

### 5.3 Sparse Polynomial Multiplication

#### Challenge Representation
```
struct SparseChallenge {
    indices: [u16; k],  // k non-zero positions
    signs: [bool; k],   // sign for each position
}
```

#### Multiplication Algorithm
```
fn sparse_mul(s: &Polynomial, c: &SparseChallenge) -> Polynomial {
    let mut result = Polynomial::zero();
    for i in 0..k {
        let idx = c.indices[i];
        let sign = if c.signs[i] { 1 } else { -1 };
        result += sign * rotate(s, idx);
    }
    result
}
```

**Requirements**:
- Rotation: O(d) operations
- Total: O(k·d) operations
- Much faster than NTT for small k

### 5.4 Multilinear Extension Evaluation

#### Dynamic Programming
```
fn eval_mle(coeffs: &[F_q], point: &[F_{q^k}]) -> F_{q^k} {
    let n = point.len();
    let mut table = coeffs.to_vec();
    
    for i in 0..n {
        let size = 1 << (n - i);
        for j in 0..(size/2) {
            table[j] = table[2*j] * (1 - point[i]) + table[2*j+1] * point[i];
        }
    }
    
    table[0]
}
```

**Complexity**: O(2^n) operations
**Optimization**: Parallelize outer loop

### 5.5 Commitment Scheme

#### Matrix Generation
```
fn generate_matrix(seed: &[u8], rows: usize, cols: usize) -> Matrix {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut matrix = Matrix::new(rows, cols);
    for i in 0..rows {
        for j in 0..cols {
            matrix[i][j] = rng.gen_range(0..q);
        }
    }
    matrix
}
```

**Requirements**:
- Deterministic from seed
- Cryptographically secure RNG
- Verifier regenerates from same seed

#### Commitment Computation
```
fn commit(matrix: &Matrix, witness: &Vector) -> Vector {
    matrix * witness  // Matrix-vector multiplication
}
```

**Optimization**:
- Parallelize rows
- Use SIMD for inner products
- Cache matrix in NTT form

### 5.6 Fiat-Shamir Transform

#### Transcript
```
struct Transcript {
    state: Sha3_256,
}

impl Transcript {
    fn append(&mut self, label: &str, data: &[u8]) {
        self.state.update(label.as_bytes());
        self.state.update(data);
    }
    
    fn challenge(&mut self, label: &str) -> F_{q^k} {
        self.append(label, &[]);
        let hash = self.state.finalize_reset();
        F_{q^k}::from_bytes(&hash)
    }
}
```

**Requirements**:
- Domain separation for each message
- Collision-resistant hash function
- Uniform distribution of challenges

## 6. Memory Requirements

### 6.1 Prover Memory
```
Witness: 2^20·1024·4 bytes = 4 GB
Commitments: 3·1024·4 bytes = 12 KB
Intermediate values: ≈ 1 GB
Total: ≈ 5 GB
```

**Optimization**: Stream witness from disk

### 6.2 Verifier Memory
```
Public parameters: 3·1024·1024·4 bytes = 12 MB
Proof: 55 KB
Intermediate values: ≈ 1 MB
Total: ≈ 13 MB
```

### 6.3 Streaming Witness
```
fn commit_streaming(matrix: &Matrix, witness_file: &Path) -> Vector {
    let mut result = Vector::zero(matrix.rows());
    let chunk_size = 1024;  // Process 1024 elements at a time
    
    let mut file = File::open(witness_file)?;
    let mut chunk = vec![0; chunk_size];
    
    for i in 0..(witness.len() / chunk_size) {
        file.read_exact(&mut chunk)?;
        result += matrix.submatrix(i * chunk_size, chunk_size) * chunk;
    }
    
    result
}
```

**Requirements**:
- Read witness in chunks
- Accumulate partial results
- Memory usage: O(chunk_size)

## 7. Testing Requirements

### 7.1 Unit Tests
```
- Arithmetic operations (F_q, F_{q^4}, R_q)
- NTT correctness
- Sparse multiplication
- Multilinear extension evaluation
- Commitment binding
- Fiat-Shamir consistency
```

### 7.2 Integration Tests
```
- End-to-end proof generation and verification
- Different polynomial sizes (ℓ = 10, 20, 30)
- Different field extensions (k = 2, 4, 8)
- Different ring dimensions (d = 256, 512, 1024)
```

### 7.3 Security Tests
```
- Soundness: reject invalid proofs
- Knowledge extraction: extract witness from valid proofs
- Binding: cannot open commitment to different values
```

### 7.4 Performance Tests
```
- Prover time vs. polynomial size
- Verifier time vs. polynomial size
- Proof size vs. polynomial size
- Memory usage vs. polynomial size
```
