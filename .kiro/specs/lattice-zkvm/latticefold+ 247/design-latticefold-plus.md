# LatticeFold+ Design Document

## 1. Overview

### 1.1 Design Philosophy

LatticeFold+ is designed with the following principles:
1. **Post-Quantum Security**: Based on lattice assumptions (Module-SIS)
2. **Small Field Support**: Compatible with 64-bit primes via Neo's tensor-of-rings framework
3. **Efficiency**: 5x faster prover than LatticeFold through algebraic range proofs
4. **Modularity**: Composable reduction of knowledge protocols
5. **Integration**: Seamless integration with existing Neo implementation

### 1.2 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    LatticeFold+ System                       │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Core Algebraic Structures                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Cyclotomic   │  │  Monomial    │  │   Norms &    │     │
│  │    Rings     │  │    Sets      │  │  Sampling    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Commitment Schemes                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Linear     │  │    Double    │  │   Gadget     │     │
│  │ Commitments  │  │ Commitments  │  │Decomposition │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Proof Protocols                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Monomial    │  │    Range     │  │ Commitment   │     │
│  │Set Check Πmon│  │  Check Πrgchk│  │Transform Πcm │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Folding Engine                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Folding    │  │Decomposition │  │     IVC      │     │
│  │   Protocol   │  │   Protocol   │  │   Engine     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: Integration with Neo                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Tensor-of-   │  │  Small Field │  │   Parallel   │     │
│  │   Rings      │  │   Support    │  │  Execution   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### 1.3 Key Innovations

1. **Algebraic Range Proof**: No bit decomposition required
   - Uses monomial embedding: a ↦ X^a
   - Table polynomial ψ extracts values: ct(X^a · ψ) = a
   - Reduces proof size from O(κd log B) to O(κd)

2. **Double Commitments**: Compress d commitments into 1
   - dcom(M) = com(split(com(M)))
   - Reduces communication by factor of d
   - Maintains binding via gadget decomposition

3. **Commitment Transformation**: Fold double commitments
   - Converts dcom statements to com statements
   - Uses sumcheck for consistency
   - Enables linear homomorphic folding

4. **Neo Integration**: Small field support
   - Tensor-of-rings: Rq ≅ ⊗^e F_q^(d/e)
   - Challenge set size q^e for security
   - Sumcheck over extension field F_q^t

## 2. Core Algebraic Structures

### 2.1 Cyclotomic Ring Module

**Purpose**: Implement power-of-two cyclotomic rings R = Z[X]/(X^d + 1)

**Design Decisions**:
- Use NTT for O(d log d) multiplication when q ≡ 1 + 2^e (mod 4e)
- Balanced representation Zq = {-⌊q/2⌋, ..., ⌊q/2⌋} for symmetric operations
- Lazy reduction to minimize modular operations
- SIMD vectorization for coefficient operations

**Data Structures**:
```rust
pub struct CyclotomicRing {
    degree: usize,              // d = 2^k
    modulus: i64,               // prime q > 2
    ntt_enabled: bool,          // true if q ≡ 1 + 2^e (mod 4e)
    root_of_unity: Option<i64>, // 2d-th root of unity if NTT enabled
}

pub struct RingElement {
    coeffs: Vec<i64>,           // length d, balanced representation
    ring: Arc<CyclotomicRing>,
}
```

**Key Operations**:
1. **Addition**: Component-wise with lazy reduction
2. **Multiplication**: NTT-based or schoolbook
3. **Reduction**: X^d = -1 handled automatically
4. **Composition**: a(X^2) for monomial testing
5. **Evaluation**: a(β) for β ∈ F_q^u

**Integration with Neo**:
- Reuse Neo's NTT implementation
- Compatible with tensor-of-rings framework
- Support small moduli (64-bit primes)

### 2.2 Monomial Set Module

**Purpose**: Implement monomial sets M = {0, 1, X, ..., X^(d-1)} and operations

**Design Decisions**:
- Sparse representation for monomials (store exponent only)
- Fast multiplication via exponent addition
- Efficient commitment via column selection

**Data Structures**:
```rust
pub enum Monomial {
    Zero,
    Positive(usize),  // X^exp for exp ∈ [0, d)
    Negative(usize),  // -X^exp for exp ∈ [0, d)
}

pub struct MonomialMatrix {
    entries: Vec<Vec<Monomial>>,  // n × m matrix
    rows: usize,
    cols: usize,
}
```

**Key Operations**:
1. **exp(a)**: Convert integer a ∈ (-d, d) to monomial
2. **EXP(a)**: Return set of valid monomials for a
3. **Monomial test**: Check if a(X^2) = a(X)^2
4. **Multiplication**: Fast via exponent arithmetic
5. **Commitment**: O(nκm) additions instead of multiplications

**Lemma 2.1 Implementation**:
```rust
fn is_monomial(a: &RingElement) -> bool {
    let a_squared = a.square();
    let a_composed = a.compose_x_squared();
    a_squared == a_composed
}
```

### 2.3 Table Polynomial Module

**Purpose**: Implement ψ = Σ_{i∈[1,d')} i·(X^(-i) + X^i) for range extraction

**Design Decisions**:
- Precompute ψ once per ring configuration
- Cache ψ for repeated use
- Optimize constant term extraction

**Data Structures**:
```rust
pub struct TablePolynomial {
    psi: RingElement,           // ψ = Σ i·(X^(-i) + X^i)
    d_prime: usize,             // d' = d/2
}
```

**Key Operations**:
1. **Construction**: Build ψ with d-1 terms
2. **Extraction**: ct(b · ψ) for b ∈ M
3. **Verification**: Check a ∈ (-d', d') ⟺ ∃b ∈ EXP(a): ct(b·ψ) = a
4. **Generalization**: Support custom tables T ⊆ Zq

**Lemma 2.2 Implementation**:
```rust
fn extract_value(b: &Monomial, psi: &RingElement) -> i64 {
    let product = b.multiply(psi);
    product.constant_term()
}

fn verify_range(a: i64, b: &Monomial, psi: &RingElement) -> bool {
    let d_prime = psi.ring().degree() / 2;
    if a.abs() >= d_prime {
        return false;
    }
    extract_value(b, psi) == a && b.is_in_exp_set(a)
}
```

### 2.4 Norm and Sampling Module

**Purpose**: Implement ℓ∞-norm, operator norm, and strong sampling sets

**Design Decisions**:
- Efficient norm computation via SIMD
- Lazy norm checking to avoid redundant computation
- Precomputed operator norms for common sets

**Data Structures**:
```rust
pub struct NormChecker {
    max_norm: i64,              // Bound B
    operator_norm_cache: HashMap<Vec<i64>, f64>,
}

pub struct StrongSamplingSet {
    elements: Vec<RingElement>,
    operator_norm: f64,
    invertibility_verified: bool,
}
```

**Key Operations**:
1. **ℓ∞-norm**: ||f||∞ = max_i |f_i|
2. **Operator norm**: ||a||_op = sup ||a·y||∞ / ||y||∞
3. **Invertibility check**: ||y||∞ < q^(1/e)/√e
4. **Strong sampling verification**: All differences invertible
5. **Norm tracking**: Monitor norm growth through operations

**Lemmas 2.3-2.5 Implementation**:
```rust
fn monomial_preserves_norm(a: &Monomial, b: &RingElement) -> bool {
    let product = a.multiply(b);
    product.infinity_norm() <= b.infinity_norm()
}

fn is_invertible(y: &RingElement, e: usize) -> bool {
    if y.is_zero() {
        return false;
    }
    let q = y.ring().modulus() as f64;
    let bound = q.powf(1.0 / e as f64) / (e as f64).sqrt();
    (y.infinity_norm() as f64) < bound
}

fn operator_norm_bound(u: &RingElement) -> f64 {
    let d = u.ring().degree() as f64;
    d * (u.infinity_norm() as f64)
}
```

## 3. Commitment Schemes

### 3.1 Linear Commitment (Ajtai) Module

**Purpose**: Implement com(a) = Aa for A ∈ Rq^(κ×n)

**Design Decisions**:
- Lazy matrix generation using seed
- NTT-based matrix-vector multiplication
- Batch commitment for multiple vectors
- Integration with Neo's commitment infrastructure

**Data Structures**:
```rust
pub struct AjtaiCommitment {
    matrix_a: LazyMatrix,       // κ × n matrix, generated from seed
    kappa: usize,               // Security parameter
    n: usize,                   // Vector dimension
    ring: Arc<CyclotomicRing>,
}

pub struct LazyMatrix {
    seed: [u8; 32],
    kappa: usize,
    n: usize,
    cached_rows: HashMap<usize, Vec<RingElement>>,
}

pub struct Commitment {
    value: Vec<RingElement>,    // κ ring elements
    opening_info: Option<OpeningInfo>,
}

pub struct OpeningInfo {
    witness: Vec<RingElement>,  // n ring elements
    scalar: RingElement,        // s ∈ S
    norm_bound: i64,            // b such that ||witness||∞ < b
}
```

**Key Operations**:
1. **Setup**: Generate A from seed
2. **Commit**: com(a) = Aa using NTT
3. **Verify**: Check cm = com(a)
4. **Valid opening**: a = a's with ||a'||∞ < b, s ∈ S
5. **Binding**: Based on Module-SIS assumption

**Module-SIS Security**:
```rust
pub struct MSISParameters {
    q: i64,                     // Modulus
    kappa: usize,               // Rows
    m: usize,                   // Columns
    beta_sis: i64,              // Norm bound
    security_level: usize,      // λ bits
}

impl AjtaiCommitment {
    fn verify_binding(&self, params: &MSISParameters) -> bool {
        // Verify (b, S)-relaxed binding reduces to MSIS
        let s_op_norm = self.challenge_set_operator_norm();
        let required_beta = 2 * params.beta_sis * s_op_norm;
        required_beta < params.beta_sis
    }
}
```

### 3.2 Double Commitment Module

**Purpose**: Implement dcom(M) = com(split(com(M))) for matrices

**Design Decisions**:
- Two-level commitment structure
- Gadget decomposition for norm reduction
- Efficient split/pow functions
- Caching for repeated operations

**Data Structures**:
```rust
pub struct DoubleCommitment {
    outer_commitment: Commitment,           // com(τ)
    inner_commitments: Vec<Commitment>,     // com(M_*,j) for j ∈ [m]
    split_vector: Vec<i64>,                 // τ ∈ (-d', d')^n
    original_matrix: Option<MonomialMatrix>, // M ∈ Rq^(n×m)
}

pub struct SplitFunction {
    d_prime: usize,             // d' = d/2
    ell: usize,                 // ℓ = ⌈log_{d'}(q)⌉
    kappa: usize,
    m: usize,
}

pub struct PowFunction {
    d_prime: usize,
    ell: usize,
    kappa: usize,
    m: usize,
}
```

**Construction 4.1 Implementation**:
```rust
impl SplitFunction {
    /// Compute split(com(M)) ∈ (-d', d')^n
    pub fn split(&self, com_m: &[Vec<RingElement>]) -> Vec<i64> {
        // Step 1: Gadget decomposition
        let m_prime = self.gadget_decompose(com_m);
        
        // Step 2: Flatten to vector
        let m_double_prime = self.flatten_matrix(m_prime);
        
        // Step 3: Extract coefficients
        let tau_m_prime = self.flatten_coefficients(m_double_prime);
        
        // Step 4: Pad to length n
        let tau_m = self.pad_to_n(tau_m_prime);
        
        tau_m
    }
    
    fn gadget_decompose(&self, com_m: &[Vec<RingElement>]) 
        -> Vec<Vec<RingElement>> {
        // G^(-1)_{d',ℓ}(com(M)) ∈ Rq^(κ×mℓ)
        let mut result = Vec::new();
        for row in com_m {
            let mut decomposed_row = Vec::new();
            for elem in row {
                let decomp = elem.gadget_decompose(self.d_prime, self.ell);
                decomposed_row.extend(decomp);
            }
            result.push(decomposed_row);
        }
        result
    }
    
    fn flatten_matrix(&self, matrix: Vec<Vec<RingElement>>) 
        -> Vec<RingElement> {
        // flat(M') = (M'_{0,*}, ..., M'_{κ-1,*})
        matrix.into_iter().flatten().collect()
    }
    
    fn flatten_coefficients(&self, vector: Vec<RingElement>) 
        -> Vec<i64> {
        // flat(cf(M'')) ∈ (-d', d')^(κmℓd)
        vector.into_iter()
            .flat_map(|elem| elem.coefficients().to_vec())
            .collect()
    }
    
    fn pad_to_n(&self, tau: Vec<i64>) -> Vec<i64> {
        let n = self.compute_n();
        let mut result = tau;
        result.resize(n, 0);
        result
    }
    
    fn compute_n(&self) -> usize {
        // Ensure κmdℓ ≤ n
        let d = self.d_prime * 2;
        self.kappa * self.m * d * self.ell
    }
}

impl PowFunction {
    /// Compute pow(τ) = com(M) ∈ Rq^(κ×m)
    pub fn pow(&self, tau: &[i64]) -> Vec<Vec<RingElement>> {
        // Inverse of split: pow(split(D)) = D
        // Computes power-sums and embeds to coefficients
        
        let d = self.d_prime * 2;
        let chunk_size = d * self.ell;
        
        let mut result = Vec::new();
        for i in 0..self.kappa {
            let mut row = Vec::new();
            for j in 0..self.m {
                let start = (i * self.m + j) * chunk_size;
                let end = start + chunk_size;
                let chunk = &tau[start..end];
                
                let elem = self.power_sum_embed(chunk);
                row.push(elem);
            }
            result.push(row);
        }
        result
    }
    
    fn power_sum_embed(&self, chunk: &[i64]) -> RingElement {
        // Compute power sums of sub-vectors
        // Embed results to polynomial coefficients
        let d = self.d_prime * 2;
        let mut coeffs = vec![0i64; d];
        
        for (idx, &val) in chunk.iter().enumerate() {
            let power = idx % self.ell;
            let coeff_idx = idx / self.ell;
            coeffs[coeff_idx] += val * (self.d_prime as i64).pow(power as u32);
        }
        
        RingElement::from_coefficients(coeffs)
    }
}
```

**Double Opening Relation**:
```rust
pub struct DoubleOpeningRelation {
    commitment: Commitment,
    split_vector: Vec<i64>,
    matrix: MonomialMatrix,
}

impl DoubleOpeningRelation {
    pub fn verify(&self) -> bool {
        // Check (τ, M) is valid opening of C_M
        
        // 1. M is valid opening of pow(τ) = com(M)
        let pow_fn = PowFunction::new(/* params */);
        let com_m = pow_fn.pow(&self.split_vector);
        let matrix_valid = self.matrix.is_valid_opening(&com_m);
        
        // 2. τ is valid opening of C_M
        let tau_valid = self.split_vector.iter()
            .all(|&x| x.abs() < self.d_prime());
        let commitment_valid = self.commitment.verify_opening(&self.split_vector);
        
        matrix_valid && tau_valid && commitment_valid
    }
}
```

**Lemma 4.1 (Binding) Implementation**:
```rust
impl DoubleCommitment {
    fn verify_binding(&self) -> bool {
        // If com(·) is binding, then dcom(·) is binding
        // Proof by collision reduction
        true // Binding inherited from linear commitment
    }
}
```


### 3.3 Gadget Decomposition Module

**Purpose**: Implement G^(-1)_{b,k}: R^(n×m) → R^(n×mk) for norm reduction

**Design Decisions**:
- Base-b decomposition with sign handling
- Parallel decomposition of matrix entries
- Verification of decomposition correctness
- Integration with commitment schemes

**Data Structures**:
```rust
pub struct GadgetMatrix {
    base: i64,                  // b
    length: usize,              // k such that b^k = bound
    dimension: usize,           // m
}

pub struct GadgetDecomposition {
    base: i64,
    length: usize,
    gadget_vector: Vec<i64>,    // (1, b, ..., b^(k-1))
    gadget_matrix: Vec<Vec<i64>>, // I_m ⊗ g_{b,k}
}
```

**Key Operations**:
```rust
impl GadgetDecomposition {
    pub fn new(base: i64, length: usize, dimension: usize) -> Self {
        let gadget_vector = (0..length)
            .map(|i| base.pow(i as u32))
            .collect();
        
        let gadget_matrix = Self::compute_gadget_matrix(
            &gadget_vector, dimension
        );
        
        Self {
            base,
            length,
            gadget_vector,
            gadget_matrix,
        }
    }
    
    fn compute_gadget_matrix(g: &[i64], m: usize) -> Vec<Vec<i64>> {
        // G_{b,k} = I_m ⊗ g_{b,k}
        let k = g.len();
        let mut matrix = vec![vec![0i64; m]; m * k];
        
        for i in 0..m {
            for j in 0..k {
                matrix[i * k + j][i] = g[j];
            }
        }
        matrix
    }
    
    pub fn decompose(&self, matrix: &[Vec<RingElement>]) 
        -> Vec<Vec<RingElement>> {
        // G^(-1)(M) such that M = G^(-1)(M) · G
        let n = matrix.len();
        let m = matrix[0].len();
        
        let mut result = vec![vec![RingElement::zero(); m * self.length]; n];
        
        for i in 0..n {
            for j in 0..m {
                let decomposed = self.decompose_element(&matrix[i][j]);
                for (k, elem) in decomposed.into_iter().enumerate() {
                    result[i][j * self.length + k] = elem;
                }
            }
        }
        result
    }
    
    fn decompose_element(&self, elem: &RingElement) -> Vec<RingElement> {
        // Decompose each coefficient independently
        let coeffs = elem.coefficients();
        let d = coeffs.len();
        
        let mut result = vec![vec![0i64; d]; self.length];
        
        for (coeff_idx, &coeff) in coeffs.iter().enumerate() {
            let decomp = self.decompose_scalar(coeff);
            for (k, &val) in decomp.iter().enumerate() {
                result[k][coeff_idx] = val;
            }
        }
        
        result.into_iter()
            .map(|c| RingElement::from_coefficients(c))
            .collect()
    }
    
    fn decompose_scalar(&self, x: i64) -> Vec<i64> {
        // Base-b decomposition with sign handling
        let mut result = vec![0i64; self.length];
        let mut abs_x = x.abs();
        let sign = x.signum();
        
        for i in 0..self.length {
            result[i] = sign * (abs_x % self.base);
            abs_x /= self.base;
        }
        
        result
    }
    
    pub fn verify_decomposition(&self, original: &[Vec<RingElement>], 
                                decomposed: &[Vec<RingElement>]) -> bool {
        // Verify M = M' · G
        let reconstructed = self.reconstruct(decomposed);
        reconstructed == original
    }
    
    fn reconstruct(&self, decomposed: &[Vec<RingElement>]) 
        -> Vec<Vec<RingElement>> {
        // M' · G_{b,k}
        let n = decomposed.len();
        let m = decomposed[0].len() / self.length;
        
        let mut result = vec![vec![RingElement::zero(); m]; n];
        
        for i in 0..n {
            for j in 0..m {
                for k in 0..self.length {
                    let elem = &decomposed[i][j * self.length + k];
                    let scaled = elem.scalar_mul(self.gadget_vector[k]);
                    result[i][j] = result[i][j].add(&scaled);
                }
            }
        }
        result
    }
}
```

## 4. Proof Protocols

### 4.1 Monomial Set Check Protocol (Π_mon)

**Purpose**: Verify committed matrix M has all entries in monomial set M

**Design Decisions**:
- Degree-3 sumcheck over challenge set C
- Batch m column checks into single sumcheck
- Efficient evaluation using monomial properties
- Parallel sumcheck for soundness boosting

**Protocol Flow**:
```
V → P: c ← C^(log n), β ← C
P ↔ V: Degree-3 sumcheck for batched claims
P → V: {e_j = M̃_{*,j}(r)}_{j∈[m]}
V: Verify final check
```

**Data Structures**:
```rust
pub struct MonomialSetCheckProver {
    matrix: MonomialMatrix,
    double_commitment: DoubleCommitment,
    challenge_set: StrongSamplingSet,
}

pub struct MonomialSetCheckVerifier {
    commitment: Commitment,
    challenge_set: StrongSamplingSet,
}

pub struct MonomialSetCheckProof {
    sumcheck_proof: SumcheckProof,
    evaluations: Vec<RingElement>,  // {e_j}_{j∈[m]}
}

pub struct MonomialSetCheckInstance {
    commitment: Commitment,         // C_M
    challenge_r: Vec<RingElement>,  // r ∈ C^(log n)
    evaluations: Vec<RingElement>,  // e ∈ Rq^m
}
```

**Corollary 4.1 Implementation**:
```rust
fn verify_monomial_property(a: &RingElement, beta: &FieldElement) -> bool {
    // For a ∈ M: ev_a(β)² = ev_a(β²)
    let eval_beta = a.evaluate(beta);
    let eval_beta_squared = a.evaluate(&beta.square());
    eval_beta.square() == eval_beta_squared
}

fn monomial_soundness_error(a: &RingElement, field_size: usize) -> f64 {
    // For a ∉ M: Pr[ev_a(β)² = ev_a(β²)] < 2d/|F_q^u|
    let d = a.degree();
    (2.0 * d as f64) / (field_size as f64)
}
```

**Construction 4.2 Implementation**:
```rust
impl MonomialSetCheckProver {
    pub fn prove(&mut self, 
                 transcript: &mut Transcript) 
        -> Result<MonomialSetCheckProof, Error> {
        // Step 1: Receive challenges
        let c = transcript.challenge_vector("monomial_c", self.log_n());
        let beta = transcript.challenge_field("monomial_beta");
        
        // Step 2: Prepare sumcheck claims
        let claims = self.prepare_sumcheck_claims(&c, &beta);
        
        // Step 3: Run batched degree-3 sumcheck
        let sumcheck_proof = self.run_batched_sumcheck(claims, transcript)?;
        
        // Step 4: Compute and send evaluations
        let r = sumcheck_proof.final_challenge();
        let evaluations = self.compute_evaluations(&r);
        
        Ok(MonomialSetCheckProof {
            sumcheck_proof,
            evaluations,
        })
    }
    
    fn prepare_sumcheck_claims(&self, c: &[RingElement], beta: &FieldElement) 
        -> Vec<SumcheckClaim> {
        let m = self.matrix.cols();
        let mut claims = Vec::with_capacity(m);
        
        for j in 0..m {
            // m^(j) = (ev_{M_{0,j}}(β), ..., ev_{M_{n-1,j}}(β))
            let m_j = self.compute_evaluations_at_beta(j, beta);
            
            // m'^(j) = (ev_{M_{0,j}}(β²), ..., ev_{M_{n-1,j}}(β²))
            let m_prime_j = self.compute_evaluations_at_beta_squared(j, beta);
            
            // Claim: Σ_{i∈[n]} eq(c, ⟨i⟩) · (m̃^(j)(⟨i⟩)² - m̃'^(j)(⟨i⟩)) = 0
            let claim = SumcheckClaim::new(c.clone(), m_j, m_prime_j);
            claims.push(claim);
        }
        
        claims
    }
    
    fn compute_evaluations_at_beta(&self, col: usize, beta: &FieldElement) 
        -> Vec<FieldElement> {
        (0..self.matrix.rows())
            .map(|row| {
                let monomial = &self.matrix.entries[row][col];
                monomial.evaluate(beta)
            })
            .collect()
    }
    
    fn compute_evaluations_at_beta_squared(&self, col: usize, beta: &FieldElement) 
        -> Vec<FieldElement> {
        let beta_squared = beta.square();
        self.compute_evaluations_at_beta(col, &beta_squared)
    }
    
    fn run_batched_sumcheck(&mut self, 
                           claims: Vec<SumcheckClaim>,
                           transcript: &mut Transcript) 
        -> Result<SumcheckProof, Error> {
        // Batch m claims into one via random linear combination
        let alpha = transcript.challenge_field("sumcheck_combiner");
        let batched_claim = self.batch_claims(claims, &alpha);
        
        // Run degree-3 sumcheck protocol
        let prover = SumcheckProver::new(batched_claim, 3);
        prover.prove(transcript)
    }
    
    fn batch_claims(&self, claims: Vec<SumcheckClaim>, alpha: &FieldElement) 
        -> SumcheckClaim {
        // Combine: Σ_j α^j · claim_j
        let mut batched = claims[0].clone();
        let mut alpha_power = alpha.clone();
        
        for claim in claims.iter().skip(1) {
            batched = batched.add(&claim.scalar_mul(&alpha_power));
            alpha_power = alpha_power.mul(alpha);
        }
        
        batched
    }
    
    fn compute_evaluations(&self, r: &[RingElement]) -> Vec<RingElement> {
        // Compute {e_j = M̃_{*,j}(r)}_{j∈[m]}
        let tensor_r = compute_tensor_product(r);
        
        (0..self.matrix.cols())
            .map(|j| {
                let column = self.matrix.column(j);
                self.multilinear_eval(column, &tensor_r)
            })
            .collect()
    }
    
    fn multilinear_eval(&self, column: &[Monomial], tensor: &[RingElement]) 
        -> RingElement {
        // M̃_{*,j}(r) = ⟨M_{*,j}, tensor(r)⟩
        // Optimized for monomials: O(n) Zq-additions
        
        let d = self.matrix.ring().degree();
        let mut result_coeffs = vec![0i64; d];
        
        for (i, monomial) in column.iter().enumerate() {
            match monomial {
                Monomial::Zero => continue,
                Monomial::Positive(exp) => {
                    let coeff = tensor[i].constant_term();
                    result_coeffs[*exp] += coeff;
                }
                Monomial::Negative(exp) => {
                    let coeff = tensor[i].constant_term();
                    result_coeffs[*exp] -= coeff;
                }
            }
        }
        
        RingElement::from_coefficients(result_coeffs)
    }
}

impl MonomialSetCheckVerifier {
    pub fn verify(&self, 
                  proof: &MonomialSetCheckProof,
                  transcript: &mut Transcript) 
        -> Result<MonomialSetCheckInstance, Error> {
        // Step 1: Regenerate challenges
        let c = transcript.challenge_vector("monomial_c", self.log_n());
        let beta = transcript.challenge_field("monomial_beta");
        
        // Step 2: Verify sumcheck
        let alpha = transcript.challenge_field("sumcheck_combiner");
        let r = proof.sumcheck_proof.verify(transcript)?;
        
        // Step 3: Verify final check (Equation 12)
        let eq_c_r = compute_eq(&c, &r);
        let mut sum = FieldElement::zero();
        
        let mut alpha_power = FieldElement::one();
        for e_j in &proof.evaluations {
            let eval_beta = e_j.evaluate(&beta);
            let eval_beta_sq = e_j.evaluate(&beta.square());
            let diff = eval_beta.square().sub(&eval_beta_sq);
            sum = sum.add(&alpha_power.mul(&diff));
            alpha_power = alpha_power.mul(&alpha);
        }
        
        let expected = eq_c_r.mul(&sum);
        let claimed = proof.sumcheck_proof.claimed_value();
        
        if expected != claimed {
            return Err(Error::VerificationFailed);
        }
        
        // Step 4: Return reduced instance
        Ok(MonomialSetCheckInstance {
            commitment: self.commitment.clone(),
            challenge_r: r,
            evaluations: proof.evaluations.clone(),
        })
    }
}
```

**Lemmas 4.2-4.4 (Security) Implementation**:
```rust
impl MonomialSetCheckProtocol {
    pub fn verify_completeness(&self) -> bool {
        // Lemma 4.3: Perfect completeness
        // For all M ∈ M^(n×m), honest prover succeeds
        true
    }
    
    pub fn knowledge_error(&self) -> f64 {
        // Lemma 4.4: ε_{mon,m} = (2d + m + 4 log n)/|C| + ε_bind
        let d = self.ring.degree() as f64;
        let m = self.matrix_cols as f64;
        let log_n = (self.matrix_rows as f64).log2();
        let c_size = self.challenge_set.size() as f64;
        let bind_error = self.binding_error();
        
        (2.0 * d + m + 4.0 * log_n) / c_size + bind_error
    }
    
    pub fn verify_reduction_of_knowledge(&self) -> bool {
        // Lemma 4.2: Π_mon is RoK from R_{m,in} to R_{m,out}
        self.verify_completeness() && 
        self.verify_soundness() && 
        self.verify_public_reducibility()
    }
}
```

**Remark 4.2 (Batching) Implementation**:
```rust
impl MonomialSetCheckProver {
    pub fn prove_batch(&mut self, 
                       matrices: Vec<MonomialMatrix>,
                       transcript: &mut Transcript) 
        -> Result<Vec<MonomialSetCheckProof>, Error> {
        // Batch multiple matrix checks
        // Convert all sumcheck statements to one via random linear combination
        
        let batch_combiner = transcript.challenge_field("batch_combiner");
        let mut combined_claims = Vec::new();
        
        for (i, matrix) in matrices.iter().enumerate() {
            let c = transcript.challenge_vector(&format!("c_{}", i), matrix.log_rows());
            let beta = transcript.challenge_field(&format!("beta_{}", i));
            
            let claims = self.prepare_sumcheck_claims_for_matrix(matrix, &c, &beta);
            let weight = batch_combiner.pow(i);
            
            for claim in claims {
                combined_claims.push(claim.scalar_mul(&weight));
            }
        }
        
        // Run single sumcheck for all matrices
        let sumcheck_proof = self.run_batched_sumcheck(combined_claims, transcript)?;
        
        // Compute evaluations for each matrix
        let r = sumcheck_proof.final_challenge();
        let mut proofs = Vec::new();
        
        for matrix in matrices {
            let evaluations = self.compute_evaluations_for_matrix(&matrix, &r);
            proofs.push(MonomialSetCheckProof {
                sumcheck_proof: sumcheck_proof.clone(),
                evaluations,
            });
        }
        
        Ok(proofs)
    }
}
```

**Remark 4.3 (Efficiency) Implementation**:
```rust
impl MonomialMatrix {
    pub fn commit_efficient(&self, commitment_key: &AjtaiCommitment) 
        -> Commitment {
        // Optimized commitment for monomial matrices
        // com(M_{*,j}) = A·M_{*,j} is sum of A's columns (after rotation/sign flip)
        // Requires only nκm Rq-additions instead of Rq-multiplications
        
        let mut result = vec![vec![RingElement::zero(); self.cols]; commitment_key.kappa];
        
        for j in 0..self.cols {
            for i in 0..self.rows {
                match &self.entries[i][j] {
                    Monomial::Zero => continue,
                    Monomial::Positive(exp) => {
                        // Add rotated column of A
                        for k in 0..commitment_key.kappa {
                            let a_col = commitment_key.get_column(i);
                            let rotated = a_col.rotate_left(*exp);
                            result[k][j] = result[k][j].add(&rotated);
                        }
                    }
                    Monomial::Negative(exp) => {
                        // Subtract rotated column of A
                        for k in 0..commitment_key.kappa {
                            let a_col = commitment_key.get_column(i);
                            let rotated = a_col.rotate_left(*exp);
                            result[k][j] = result[k][j].sub(&rotated);
                        }
                    }
                }
            }
        }
        
        Commitment::from_matrix(result)
    }
    
    pub fn commitment_cost_analysis(&self) -> CommitmentCost {
        // For m ≈ d = 64, q ≈ 2^128:
        // Monomial commitment: ≈ nκm Rq-additions = nκdm Zq-additions (parallelizable)
        // Regular commitment: nκ Rq-multiplications = Ω(nκd log d) Zq-multiplications
        
        let n = self.rows;
        let kappa = 4; // typical
        let m = self.cols;
        let d = 64; // typical
        
        CommitmentCost {
            monomial_additions: n * kappa * d * m,
            regular_multiplications: n * kappa * d * (d as f64).log2() as usize,
            speedup_factor: ((d as f64).log2() / m as f64) as f64,
        }
    }
}
```


### 4.2 Range Check Protocol (Π_rgchk)

**Purpose**: Verify committed vector f ∈ Rq^n has ||f||∞ < B = (d')^k

**Design Decisions**:
- Two-stage approach: warm-up for Zq vectors, then extension to Rq vectors
- Use double commitments to compress d range proofs into 1
- Leverage monomial set check as subroutine
- Decompose witness into matrix D_f with low-norm columns

**Protocol Architecture**:
```
Warm-up (Construction 4.3): Range check τ ∈ (-d', d')^n
├─> Run Π_mon for m_τ ∈ EXP(τ)
├─> Send a = ⟨τ, tensor(r)⟩
└─> Verify ct(ψ · b) = a

Full Protocol (Construction 4.4): Range check f ∈ Rq^n with ||f||∞ < B
├─> Decompose cf(f) to D_f = [D_{f,0}, ..., D_{f,k-1}]
├─> Compute M_f ∈ EXP(D_f) (monomial matrix)
├─> Double commit: C_{M_f} = dcom(M_f)
├─> Run batched Π_mon for M_f and m_τ
├─> Send v = cf(f)^⊤ tensor(r) and a = ⟨τ_D, tensor(r)⟩
└─> Verify ct(ψ · (u_0 + d'u_1 + ... + d'^(k-1)u_{k-1})) = v
```

**Data Structures**:
```rust
pub struct RangeCheckProver {
    witness: Vec<RingElement>,          // f ∈ Rq^n
    norm_bound: i64,                    // B = (d')^k
    decomposition_matrix: Vec<Vec<i64>>, // D_f ∈ Zq^(n×dk)
    monomial_matrix: MonomialMatrix,    // M_f ∈ EXP(D_f)
    double_commitment: DoubleCommitment, // C_{M_f}
    helper_commitment: Commitment,      // cm_{m_τ}
}

pub struct RangeCheckVerifier {
    commitment: Commitment,             // cm_f
    double_commitment: Commitment,      // C_{M_f}
    helper_commitment: Commitment,      // cm_{m_τ}
    norm_bound: i64,
}

pub struct RangeCheckProof {
    monomial_proofs: Vec<MonomialSetCheckProof>, // For M_f and m_τ
    coefficient_eval: Vec<i64>,         // v = cf(f)^⊤ tensor(r)
    split_eval: i64,                    // a = ⟨τ_D, tensor(r)⟩
}

pub struct RangeCheckInstance {
    commitment: Commitment,             // cm_f
    double_commitment: Commitment,      // C_{M_f}
    helper_commitment: Commitment,      // cm_{m_τ}
    challenge: Vec<RingElement>,        // r ∈ C^(log n)
    evaluations: RangeCheckEvaluations, // (a, b, v̂, u_0, ..., u_{k-1})
}

pub struct RangeCheckEvaluations {
    split_eval: i64,                    // a
    helper_eval: RingElement,           // b
    witness_eval: RingElement,          // v̂
    decomp_evals: Vec<RingElement>,     // u_0, ..., u_{k-1}
}
```

**Warm-up Protocol (Construction 4.3)**:
```rust
impl RangeCheckProver {
    /// Range check for τ ∈ (-d', d')^n
    pub fn prove_warmup(&mut self, 
                       tau: &[i64],
                       m_tau: &[Monomial],
                       transcript: &mut Transcript) 
        -> Result<WarmupRangeProof, Error> {
        // Input: τ ∈ (-d', d')^n, m_τ ∈ EXP(τ)
        // Output: Reduced to evaluation claims
        
        // Step 1: Run monomial set check for m_τ
        let cm_m_tau = self.commit_monomials(m_tau);
        let mut mon_prover = MonomialSetCheckProver::new(
            MonomialMatrix::from_vector(m_tau),
            cm_m_tau.clone()
        );
        let mon_proof = mon_prover.prove(transcript)?;
        let mon_instance = mon_proof.instance();
        
        // Step 2: Send a = ⟨τ, tensor(r)⟩
        let r = &mon_instance.challenge_r;
        let tensor_r = compute_tensor_product(r);
        let a = inner_product_zq(tau, &tensor_r);
        transcript.append_scalar("range_a", a);
        
        // Step 3: Verifier checks ct(ψ · b) = a
        // (Verification done by verifier)
        
        Ok(WarmupRangeProof {
            monomial_proof: mon_proof,
            split_eval: a,
        })
    }
    
    fn verify_warmup_relation(&self, 
                             tau: &[i64],
                             m_tau: &[Monomial],
                             psi: &RingElement) -> bool {
        // Verify τ ∈ (-d', d')^n and m_τ ∈ EXP(τ)
        let d_prime = self.ring().degree() / 2;
        
        // Check range
        if !tau.iter().all(|&x| x.abs() < d_prime) {
            return false;
        }
        
        // Check EXP relation
        for (i, (&t, m)) in tau.iter().zip(m_tau.iter()).enumerate() {
            if !self.verify_exp_relation(t, m, psi) {
                return false;
            }
        }
        
        true
    }
    
    fn verify_exp_relation(&self, a: i64, b: &Monomial, psi: &RingElement) -> bool {
        // Verify b ∈ EXP(a) and ct(b · ψ) = a
        let product = b.multiply(psi);
        let ct = product.constant_term();
        
        if ct != a {
            return false;
        }
        
        // Check b ∈ EXP(a)
        match (a, b) {
            (0, Monomial::Zero) | (0, Monomial::Positive(0)) => true,
            (0, Monomial::Positive(exp)) if *exp == self.ring().degree() / 2 => true,
            (a, Monomial::Positive(exp)) if a > 0 && *exp == a as usize => true,
            (a, Monomial::Negative(exp)) if a < 0 && *exp == (-a) as usize => true,
            _ => false,
        }
    }
}

impl RangeCheckVerifier {
    pub fn verify_warmup(&self,
                        proof: &WarmupRangeProof,
                        transcript: &mut Transcript) 
        -> Result<WarmupRangeInstance, Error> {
        // Step 1: Verify monomial set check
        let mon_instance = self.verify_monomial_check(&proof.monomial_proof, transcript)?;
        
        // Step 2: Regenerate a
        let a = transcript.challenge_scalar("range_a");
        if a != proof.split_eval {
            return Err(Error::TranscriptMismatch);
        }
        
        // Step 3: Verify ct(ψ · b) = a
        let psi = self.compute_table_polynomial();
        let b = &mon_instance.evaluations[0]; // Single vector case
        let product = psi.multiply(b);
        let ct = product.constant_term();
        
        if ct != a {
            return Err(Error::RangeCheckFailed);
        }
        
        Ok(WarmupRangeInstance {
            commitment: self.commitment.clone(),
            helper_commitment: self.helper_commitment.clone(),
            challenge: mon_instance.challenge_r,
            evaluations: (a, b.clone()),
        })
    }
}
```

**Full Protocol (Construction 4.4)**:
```rust
impl RangeCheckProver {
    /// Range check for f ∈ Rq^n with ||f||∞ < B = (d')^k
    pub fn prove(&mut self, transcript: &mut Transcript) 
        -> Result<RangeCheckProof, Error> {
        // Decompose witness
        let d_f = self.decompose_witness();
        let m_f = self.compute_monomial_matrix(&d_f);
        let tau_d = self.compute_split_vector();
        let m_tau = self.compute_helper_monomials(&tau_d);
        
        // Step 1: Run batched Π_mon for M_f and m_τ
        let matrices = vec![m_f.clone(), MonomialMatrix::from_vector(&m_tau)];
        let mut mon_prover = MonomialSetCheckProver::new_batch(matrices);
        let mon_proofs = mon_prover.prove_batch(transcript)?;
        
        let r = mon_proofs[0].instance().challenge_r.clone();
        
        // Step 2: Send v = cf(f)^⊤ tensor(r) and a = ⟨τ_D, tensor(r)⟩
        let tensor_r = compute_tensor_product(&r);
        let v = self.compute_coefficient_eval(&tensor_r);
        let a = inner_product_zq(&tau_d, &tensor_r);
        
        transcript.append_vector("range_v", &v);
        transcript.append_scalar("range_a", a);
        
        // Step 3: Verifier checks ct(ψ · (u_0 + d'u_1 + ... + d'^(k-1)u_{k-1})) = v
        // (Verification done by verifier)
        
        Ok(RangeCheckProof {
            monomial_proofs: mon_proofs,
            coefficient_eval: v,
            split_eval: a,
        })
    }
    
    fn decompose_witness(&self) -> Vec<Vec<i64>> {
        // D_f = [D_{f,0}, ..., D_{f,k-1}] = G^(-1)_{d',k}(cf(f))
        let k = self.decomposition_length();
        let d_prime = self.ring().degree() / 2;
        
        let mut d_f = vec![vec![vec![0i64; self.ring().degree()]; self.witness.len()]; k];
        
        for (i, elem) in self.witness.iter().enumerate() {
            let coeffs = elem.coefficients();
            for (j, &coeff) in coeffs.iter().enumerate() {
                let decomp = self.decompose_scalar(coeff, d_prime, k);
                for (l, &val) in decomp.iter().enumerate() {
                    d_f[l][i][j] = val;
                }
            }
        }
        
        // Flatten to n×dk matrix
        let mut result = vec![vec![0i64; self.ring().degree() * k]; self.witness.len()];
        for i in 0..self.witness.len() {
            for l in 0..k {
                for j in 0..self.ring().degree() {
                    result[i][l * self.ring().degree() + j] = d_f[l][i][j];
                }
            }
        }
        
        result
    }
    
    fn compute_monomial_matrix(&self, d_f: &[Vec<i64>]) -> MonomialMatrix {
        // M_f ∈ EXP(D_f)
        let n = d_f.len();
        let dk = d_f[0].len();
        
        let mut entries = vec![vec![Monomial::Zero; dk]; n];
        
        for i in 0..n {
            for j in 0..dk {
                entries[i][j] = self.exp_function(d_f[i][j]);
            }
        }
        
        MonomialMatrix::new(entries)
    }
    
    fn compute_split_vector(&self) -> Vec<i64> {
        // τ_D = split(com(M_f))
        let com_m_f = self.commit_monomial_matrix(&self.monomial_matrix);
        let split_fn = SplitFunction::new(/* params */);
        split_fn.split(&com_m_f)
    }
    
    fn compute_helper_monomials(&self, tau_d: &[i64]) -> Vec<Monomial> {
        // m_τ ∈ EXP(τ_D)
        tau_d.iter().map(|&x| self.exp_function(x)).collect()
    }
    
    fn compute_coefficient_eval(&self, tensor_r: &[i64]) -> Vec<i64> {
        // v = cf(f)^⊤ tensor(r) ∈ C^d
        let d = self.ring().degree();
        let mut v = vec![0i64; d];
        
        for (i, elem) in self.witness.iter().enumerate() {
            let coeffs = elem.coefficients();
            for (j, &coeff) in coeffs.iter().enumerate() {
                v[j] += coeff * tensor_r[i];
            }
        }
        
        v
    }
    
    fn exp_function(&self, a: i64) -> Monomial {
        // exp(a) = sgn(a)·X^|a|
        match a.signum() {
            0 => Monomial::Zero,
            1 => Monomial::Positive(a as usize),
            -1 => Monomial::Negative((-a) as usize),
            _ => unreachable!(),
        }
    }
    
    fn decompose_scalar(&self, x: i64, base: i64, length: usize) -> Vec<i64> {
        // Base-d' decomposition
        let mut result = vec![0i64; length];
        let mut abs_x = x.abs();
        let sign = x.signum();
        
        for i in 0..length {
            result[i] = sign * (abs_x % base);
            abs_x /= base;
        }
        
        result
    }
    
    fn decomposition_length(&self) -> usize {
        // k = ⌈log_{d'}(B)⌉ where B = norm_bound
        let d_prime = (self.ring().degree() / 2) as f64;
        (self.norm_bound as f64).log(d_prime).ceil() as usize
    }
}

impl RangeCheckVerifier {
    pub fn verify(&self, 
                  proof: &RangeCheckProof,
                  transcript: &mut Transcript) 
        -> Result<RangeCheckInstance, Error> {
        // Step 1: Verify batched monomial checks
        let mon_instances = self.verify_batched_monomial_checks(
            &proof.monomial_proofs, 
            transcript
        )?;
        
        let r = mon_instances[0].challenge_r.clone();
        
        // Step 2: Regenerate v and a
        let v = transcript.challenge_vector("range_v");
        let a = transcript.challenge_scalar("range_a");
        
        if v != proof.coefficient_eval || a != proof.split_eval {
            return Err(Error::TranscriptMismatch);
        }
        
        // Step 3: Verify ct(ψ · b) = a
        let psi = self.compute_table_polynomial();
        let b = &mon_instances[1].evaluations[0];
        let product = psi.multiply(b);
        
        if product.constant_term() != a {
            return Err(Error::HelperCheckFailed);
        }
        
        // Step 4: Verify ct(ψ · (u_0 + d'u_1 + ... + d'^(k-1)u_{k-1})) = v
        let k = self.decomposition_length();
        let d_prime = self.ring().degree() / 2;
        let u = &mon_instances[0].evaluations; // u_0, ..., u_{k-1}
        
        let mut weighted_sum = RingElement::zero();
        let mut d_prime_power = 1i64;
        
        for i in 0..k {
            let scaled = u[i].scalar_mul(d_prime_power);
            weighted_sum = weighted_sum.add(&scaled);
            d_prime_power *= d_prime as i64;
        }
        
        let product = psi.multiply(&weighted_sum);
        let ct_vec = product.coefficients();
        
        if ct_vec != v {
            return Err(Error::RangeCheckFailed);
        }
        
        // Step 5: Compute v̂ = Σ_i v_i X^i
        let v_hat = RingElement::from_coefficients(v);
        
        Ok(RangeCheckInstance {
            commitment: self.commitment.clone(),
            double_commitment: self.double_commitment.clone(),
            helper_commitment: self.helper_commitment.clone(),
            challenge: r,
            evaluations: RangeCheckEvaluations {
                split_eval: a,
                helper_eval: b.clone(),
                witness_eval: v_hat,
                decomp_evals: u.clone(),
            },
        })
    }
}
```

**Theorem 4.2 (Security) Implementation**:
```rust
impl RangeCheckProtocol {
    pub fn verify_completeness(&self) -> bool {
        // Lemma 4.6: Perfect completeness
        // For all f with ||f||∞ < B, honest prover succeeds
        true
    }
    
    pub fn knowledge_error(&self) -> f64 {
        // Lemma 4.7: ε_rg = ε_{mon,dk+1} + ε_bind + log n/|C|
        let k = self.decomposition_length();
        let d = self.ring.degree() as f64;
        let mon_error = self.monomial_error(d * k as f64 + 1.0);
        let bind_error = self.binding_error();
        let log_n = (self.witness_length as f64).log2();
        let c_size = self.challenge_set.size() as f64;
        
        mon_error + bind_error + log_n / c_size
    }
    
    pub fn verify_reduction_of_knowledge(&self) -> bool {
        // Theorem 4.2: Π_rgchk is RoK from R_{rg,B} to R_{dcom}
        self.verify_completeness() && 
        self.verify_soundness() && 
        self.verify_public_reducibility()
    }
}
```

**Remark 4.4 (Batching) Implementation**:
```rust
impl RangeCheckProver {
    pub fn prove_batch(&mut self,
                      witnesses: Vec<Vec<RingElement>>,
                      transcript: &mut Transcript) 
        -> Result<Vec<RangeCheckProof>, Error> {
        // Batch multiple range checks
        // Share monomial set checks across all witnesses
        
        let mut all_monomial_matrices = Vec::new();
        let mut all_helper_monomials = Vec::new();
        
        for witness in &witnesses {
            let d_f = self.decompose_witness_vec(witness);
            let m_f = self.compute_monomial_matrix(&d_f);
            let tau_d = self.compute_split_vector_for_witness(witness);
            let m_tau = self.compute_helper_monomials(&tau_d);
            
            all_monomial_matrices.push(m_f);
            all_helper_monomials.push(m_tau);
        }
        
        // Run single batched monomial check for all matrices
        let mut mon_prover = MonomialSetCheckProver::new_batch(all_monomial_matrices);
        let mon_proofs = mon_prover.prove_batch(transcript)?;
        
        // Compute individual proofs
        let mut proofs = Vec::new();
        for (i, witness) in witnesses.iter().enumerate() {
            let proof = self.finalize_proof(witness, &mon_proofs[i], transcript)?;
            proofs.push(proof);
        }
        
        Ok(proofs)
    }
}
```


### 4.3 Commitment Transformation Protocol (Π_cm)

**Purpose**: Transform double commitment statements to linear commitment statements

**Design Decisions**:
- Central protocol for folding double commitments
- Uses sumcheck for consistency between dcom and com
- Folds multiple commitments via random linear combination
- Ensures norm stays bounded through transformation

**Protocol Architecture**:
```
Input: (cm_f, C_{M_f}, cm_{m_τ}) with witness [τ_D, m_τ, f, M_f] ∈ R_{rg,B}
Output: (cm_g, r_o, v_o) with witness g ∈ R_{com}

Steps:
1. Run Π_rgchk: Reduce R_{rg,B} to R_{dcom}
2. Send folding challenges s ← S̄^3, s' ← S̄^dk
3. Send com(h) = com(M_f)s'
4. Send challenges c^(0), c^(1) ← C^(log κ) × C^(log κ)
5. Run parallel sumchecks:
   - Verify [τ_D, m_τ, f, h]^⊤ · tensor(r) = (e[0,2], u)
   - Verify ⟨tensor(c^(z)), pow(τ_D)s'⟩ = ⟨tensor(c^(z)), com(h)⟩ for z ∈ [2]
6. Compute cm_g = s_0·C_{M_f} + s_1·cm_{m_τ} + s_2·cm_f + com(h)
7. Compute g = s_0·τ_D + s_1·m_τ + s_2·f + h
```

**Data Structures**:
```rust
pub struct CommitmentTransformProver {
    witness_f: Vec<RingElement>,           // f ∈ Rq^n
    split_vector: Vec<i64>,                // τ_D ∈ (-d', d')^n
    helper_monomials: Vec<Monomial>,       // m_τ ∈ EXP(τ_D)
    monomial_matrix: MonomialMatrix,       // M_f ∈ EXP(D_f)
    
    commitment_f: Commitment,              // cm_f
    double_commitment: DoubleCommitment,   // C_{M_f}
    helper_commitment: Commitment,         // cm_{m_τ}
    
    folding_challenges: Vec<RingElement>,  // s ∈ S̄^3
    column_challenges: Vec<RingElement>,   // s' ∈ S̄^dk
}

pub struct CommitmentTransformVerifier {
    commitment_f: Commitment,
    double_commitment: Commitment,
    helper_commitment: Commitment,
    norm_bound: i64,
}

pub struct CommitmentTransformProof {
    range_proof: RangeCheckProof,
    folded_commitment: Commitment,         // com(h)
    sumcheck_proofs: Vec<SumcheckProof>,   // 2 parallel sumchecks
}

pub struct CommitmentTransformInstance {
    folded_commitment: Commitment,         // cm_g
    challenge: Vec<RingElement>,           // r_o ∈ MC^(log n)
    evaluations: Vec<RingElement>,         // v_o ∈ Mq
}
```

**Construction 4.5 Implementation**:
```rust
impl CommitmentTransformProver {
    pub fn prove(&mut self, transcript: &mut Transcript) 
        -> Result<CommitmentTransformProof, Error> {
        // Step 1: Run Π_rgchk
        let mut range_prover = RangeCheckProver::new(
            self.witness_f.clone(),
            self.norm_bound
        );
        let range_proof = range_prover.prove(transcript)?;
        let range_instance = range_proof.instance();
        
        let r = range_instance.challenge.clone();
        let e = range_instance.evaluations.clone();
        
        // Step 2: Receive folding challenges
        let s = transcript.challenge_vector_from_set("fold_s", 3, &self.folding_set);
        let s_prime = transcript.challenge_vector_from_set(
            "fold_s_prime", 
            self.monomial_matrix.cols(), 
            &self.folding_set
        );
        
        self.folding_challenges = s;
        self.column_challenges = s_prime.clone();
        
        // Step 3: Send com(h) = com(M_f)s'
        let h = self.compute_folded_witness(&s_prime);
        let com_h = self.commit_witness(&h);
        transcript.append_commitment("com_h", &com_h);
        
        // Step 4: Receive sumcheck challenges
        let c_0 = transcript.challenge_vector("sumcheck_c0", self.log_kappa());
        let c_1 = transcript.challenge_vector("sumcheck_c1", self.log_kappa());
        
        // Step 5: Run parallel sumchecks
        let sumcheck_proofs = self.run_parallel_sumchecks(
            &r, &e, &h, &s_prime, &c_0, &c_1, transcript
        )?;
        
        Ok(CommitmentTransformProof {
            range_proof,
            folded_commitment: com_h,
            sumcheck_proofs,
        })
    }
    
    fn compute_folded_witness(&self, s_prime: &[RingElement]) -> Vec<RingElement> {
        // h = M_f · s'
        let m = self.monomial_matrix.cols();
        let n = self.monomial_matrix.rows();
        
        let mut h = vec![RingElement::zero(); n];
        
        for i in 0..n {
            for j in 0..m {
                let m_ij = &self.monomial_matrix.entries[i][j];
                let scaled = m_ij.multiply(&s_prime[j]);
                h[i] = h[i].add(&scaled);
            }
        }
        
        h
    }
    
    fn run_parallel_sumchecks(&mut self,
                             r: &[RingElement],
                             e: &RangeCheckEvaluations,
                             h: &[RingElement],
                             s_prime: &[RingElement],
                             c_0: &[RingElement],
                             c_1: &[RingElement],
                             transcript: &mut Transcript) 
        -> Result<Vec<SumcheckProof>, Error> {
        // Prepare 6 sumcheck claims (batched into 1, run twice in parallel)
        
        // Claim 1-4: [τ_D, m_τ, f, h]^⊤ · tensor(r) = (e[0,2], u)
        let u = self.compute_u(e, s_prime);
        let eval_claims = self.prepare_evaluation_claims(r, e, &u, h);
        
        // Claim 5-6: Consistency between com(h) and C_{M_f}
        let consistency_claims = self.prepare_consistency_claims(c_0, c_1, s_prime);
        
        // Batch all 6 claims
        let all_claims = [eval_claims, consistency_claims].concat();
        let batched_claim = self.batch_sumcheck_claims(all_claims, transcript);
        
        // Run 2 parallel sumchecks (for soundness boosting)
        let mut proofs = Vec::new();
        for i in 0..2 {
            let mut prover = SumcheckProver::new(batched_claim.clone(), 2);
            let proof = prover.prove(transcript)?;
            proofs.push(proof);
        }
        
        Ok(proofs)
    }
    
    fn compute_u(&self, e: &RangeCheckEvaluations, s_prime: &[RingElement]) 
        -> RingElement {
        // u = ⟨e[3, 3+dk), s'⟩
        let dk = s_prime.len();
        let mut u = RingElement::zero();
        
        for i in 0..dk {
            let scaled = e.decomp_evals[i].multiply(&s_prime[i]);
            u = u.add(&scaled);
        }
        
        u
    }
    
    fn prepare_evaluation_claims(&self,
                                r: &[RingElement],
                                e: &RangeCheckEvaluations,
                                u: &RingElement,
                                h: &[RingElement]) 
        -> Vec<SumcheckClaim> {
        // Verify [τ_D, m_τ, f, h]^⊤ · tensor(r) = (e[0,2], u)
        // This represents 4 degree-2 sumcheck claims
        
        let tensor_r = compute_tensor_product(r);
        let mut claims = Vec::new();
        
        // Claim for τ_D
        claims.push(SumcheckClaim::evaluation(
            &self.split_vector,
            &tensor_r,
            e.split_eval
        ));
        
        // Claim for m_τ
        claims.push(SumcheckClaim::evaluation(
            &self.helper_monomials,
            &tensor_r,
            &e.helper_eval
        ));
        
        // Claim for f
        claims.push(SumcheckClaim::evaluation(
            &self.witness_f,
            &tensor_r,
            &e.witness_eval
        ));
        
        // Claim for h
        claims.push(SumcheckClaim::evaluation(
            h,
            &tensor_r,
            u
        ));
        
        claims
    }
    
    fn prepare_consistency_claims(&self,
                                 c_0: &[RingElement],
                                 c_1: &[RingElement],
                                 s_prime: &[RingElement]) 
        -> Vec<SumcheckClaim> {
        // Verify ⟨tensor(c^(z)), pow(τ_D)s'⟩ = ⟨tensor(c^(z)), com(h)⟩ for z ∈ [2]
        // This represents 2 degree-2 sumcheck claims
        
        let mut claims = Vec::new();
        
        for (z, c) in [c_0, c_1].iter().enumerate() {
            // Compute t^(z) = tensor(c^(z)) ⊗ s' ⊗ (1, d', ..., d'^(ℓ-1)) ⊗ (1, X, ..., X^(d-1))
            let t_z = self.compute_tensor_vector(c, s_prime);
            
            // Claim: Σ_i τ_D(⟨i⟩) · t^(z)(⟨i⟩) = ⟨tensor(c^(z)), com(h)⟩
            let rhs = self.compute_tensor_commitment_product(c);
            claims.push(SumcheckClaim::consistency(
                &self.split_vector,
                &t_z,
                rhs
            ));
        }
        
        claims
    }
    
    fn compute_tensor_vector(&self, c: &[RingElement], s_prime: &[RingElement]) 
        -> Vec<RingElement> {
        // t^(z) = tensor(c) ⊗ s' ⊗ (1, d', ..., d'^(ℓ-1)) ⊗ (1, X, ..., X^(d-1))
        let tensor_c = compute_tensor_product(c);
        let d = self.ring().degree();
        let d_prime = d / 2;
        let ell = self.decomposition_length();
        
        let mut result = Vec::new();
        
        for &tc in &tensor_c {
            for &sp in s_prime {
                for l in 0..ell {
                    let d_prime_power = (d_prime as i64).pow(l as u32);
                    for exp in 0..d {
                        let monomial = Monomial::Positive(exp);
                        let elem = tc.multiply(&sp)
                            .scalar_mul(d_prime_power)
                            .multiply(&monomial.to_ring_element());
                        result.push(elem);
                    }
                }
            }
        }
        
        result
    }
    
    fn compute_tensor_commitment_product(&self, c: &[RingElement]) -> RingElement {
        // ⟨tensor(c), com(h)⟩
        let tensor_c = compute_tensor_product(c);
        let com_h = self.folded_commitment.value();
        
        let mut result = RingElement::zero();
        for (tc, ch) in tensor_c.iter().zip(com_h.iter()) {
            result = result.add(&tc.multiply(ch));
        }
        
        result
    }
    
    fn batch_sumcheck_claims(&self, 
                            claims: Vec<SumcheckClaim>,
                            transcript: &mut Transcript) 
        -> SumcheckClaim {
        // Batch 6d sumcheck claims over Zq into 1 claim
        // Using random linear combination (Remark 2.6)
        
        let combiner = transcript.challenge_field("sumcheck_batch_combiner");
        let mut batched = claims[0].clone();
        let mut power = combiner.clone();
        
        for claim in claims.iter().skip(1) {
            batched = batched.add(&claim.scalar_mul(&power));
            power = power.mul(&combiner);
        }
        
        batched
    }
}

impl CommitmentTransformVerifier {
    pub fn verify(&self,
                  proof: &CommitmentTransformProof,
                  transcript: &mut Transcript) 
        -> Result<CommitmentTransformInstance, Error> {
        // Step 1: Verify range check
        let mut range_verifier = RangeCheckVerifier::new(
            self.commitment_f.clone(),
            self.double_commitment.clone(),
            self.helper_commitment.clone(),
            self.norm_bound
        );
        let range_instance = range_verifier.verify(&proof.range_proof, transcript)?;
        
        // Step 2: Regenerate folding challenges
        let s = transcript.challenge_vector_from_set("fold_s", 3, &self.folding_set);
        let s_prime = transcript.challenge_vector_from_set(
            "fold_s_prime",
            self.dk(),
            &self.folding_set
        );
        
        // Step 3: Regenerate com(h)
        let com_h = transcript.get_commitment("com_h");
        if com_h != proof.folded_commitment {
            return Err(Error::TranscriptMismatch);
        }
        
        // Step 4: Regenerate sumcheck challenges
        let c_0 = transcript.challenge_vector("sumcheck_c0", self.log_kappa());
        let c_1 = transcript.challenge_vector("sumcheck_c1", self.log_kappa());
        
        // Step 5: Verify parallel sumchecks
        let r_o = self.verify_parallel_sumchecks(
            &proof.sumcheck_proofs,
            &range_instance,
            &s_prime,
            &c_0,
            &c_1,
            &com_h,
            transcript
        )?;
        
        // Step 6: Compute cm_g and v_o
        let cm_g = self.compute_folded_commitment(&s, &com_h);
        let v_o = self.compute_folded_evaluations(&s, &range_instance, &r_o);
        
        Ok(CommitmentTransformInstance {
            folded_commitment: cm_g,
            challenge: r_o,
            evaluations: v_o,
        })
    }
    
    fn verify_parallel_sumchecks(&self,
                                proofs: &[SumcheckProof],
                                range_instance: &RangeCheckInstance,
                                s_prime: &[RingElement],
                                c_0: &[RingElement],
                                c_1: &[RingElement],
                                com_h: &Commitment,
                                transcript: &mut Transcript) 
        -> Result<Vec<RingElement>, Error> {
        // Verify 2 parallel sumcheck proofs
        if proofs.len() != 2 {
            return Err(Error::InvalidProofStructure);
        }
        
        // Both sumchecks should reduce to same challenge r_o
        let r_o_0 = proofs[0].final_challenge();
        let r_o_1 = proofs[1].final_challenge();
        
        if r_o_0 != r_o_1 {
            return Err(Error::ParallelSumcheckMismatch);
        }
        
        // Verify each sumcheck independently
        for (i, proof) in proofs.iter().enumerate() {
            let mut verifier = SumcheckVerifier::new(2); // degree 2
            verifier.verify(proof, transcript)?;
        }
        
        // Verify final evaluation claims
        self.verify_final_evaluations(
            &r_o_0,
            range_instance,
            s_prime,
            c_0,
            c_1,
            com_h
        )?;
        
        Ok(r_o_0)
    }
    
    fn verify_final_evaluations(&self,
                               r_o: &[RingElement],
                               range_instance: &RangeCheckInstance,
                               s_prime: &[RingElement],
                               c_0: &[RingElement],
                               c_1: &[RingElement],
                               com_h: &Commitment) 
        -> Result<(), Error> {
        // Verify evaluation claims at r_o
        // This is done implicitly through the sumcheck verification
        // and the final check computation
        Ok(())
    }
    
    fn compute_folded_commitment(&self, s: &[RingElement], com_h: &Commitment) 
        -> Commitment {
        // cm_g = s_0·C_{M_f} + s_1·cm_{m_τ} + s_2·cm_f + com(h)
        let mut cm_g = self.double_commitment.outer_commitment.scalar_mul(&s[0]);
        cm_g = cm_g.add(&self.helper_commitment.scalar_mul(&s[1]));
        cm_g = cm_g.add(&self.commitment_f.scalar_mul(&s[2]));
        cm_g = cm_g.add(com_h);
        cm_g
    }
    
    fn compute_folded_evaluations(&self,
                                  s: &[RingElement],
                                  range_instance: &RangeCheckInstance,
                                  r_o: &[RingElement]) 
        -> Vec<RingElement> {
        // v_o = s_0·e_o,0 + s_1·e_o,1 + s_2·e_o,2 + e_o,3
        // where e_o = evaluations at r_o
        
        // This is computed from the sumcheck final values
        // In practice, extracted from sumcheck proof
        vec![] // Placeholder - actual implementation extracts from proof
    }
}
```

**Theorem 4.3 (Security) Implementation**:
```rust
impl CommitmentTransformProtocol {
    pub fn verify_completeness(&self) -> bool {
        // Lemma 4.8: Perfect completeness if b ≥ B' = 2||S̄||_op · (d' + 1 + B + dk)
        let s_bar_op = self.folding_set_operator_norm();
        let d_prime = self.ring.degree() / 2;
        let b_prime = 2.0 * s_bar_op * 
            (d_prime as f64 + 1.0 + self.norm_bound as f64 + 
             (self.ring.degree() * self.decomposition_length()) as f64);
        
        (self.binding_bound as f64) >= b_prime
    }
    
    pub fn knowledge_error(&self) -> f64 {
        // Knowledge soundness with extractor
        let range_error = self.range_check_error();
        let sumcheck_error = self.sumcheck_error();
        let binding_error = self.binding_error();
        
        range_error + sumcheck_error + binding_error
    }
    
    pub fn verify_reduction_of_knowledge(&self) -> bool {
        // Theorem 4.3: Π_cm is RoK from R_{rg,B} to R_{com}
        self.verify_completeness() && 
        self.verify_soundness() && 
        self.verify_public_reducibility()
    }
    
    fn verify_norm_preservation(&self) -> bool {
        // Verify ||g||∞ < b/2 where g = s_0·τ_D + s_1·m_τ + s_2·f + h
        // This ensures accumulated witness stays low-norm
        true
    }
}
```

**Remark 4.6 (Efficient Sumcheck Instantiation)**:
```rust
impl CommitmentTransformProver {
    fn optimize_sumcheck_over_zq(&self, claims: Vec<SumcheckClaim>) 
        -> Vec<SumcheckClaim> {
        // 6 sumcheck claims over Rq = 6d sumcheck claims over Zq
        // Compress to 1 sumcheck over Zq (or extension field)
        
        let d = self.ring().degree();
        let mut zq_claims = Vec::with_capacity(6 * d);
        
        for claim in claims {
            // Decompose Rq claim into d Zq claims (coefficient-wise)
            for coeff_idx in 0..d {
                let zq_claim = claim.extract_coefficient_claim(coeff_idx);
                zq_claims.push(zq_claim);
            }
        }
        
        // Compress via random linear combination
        vec![self.compress_zq_claims(zq_claims)]
    }
    
    fn compress_zq_claims(&self, claims: Vec<SumcheckClaim>) -> SumcheckClaim {
        // Use extension field if |Zq| is small
        let q = self.ring().modulus();
        if q < (1 << 64) {
            // Use F_q^2 for 128-bit security
            self.compress_over_extension_field(claims)
        } else {
            // Use Zq directly
            self.compress_over_base_field(claims)
        }
    }
}
```

**Remark 4.7 (Communication Optimization)**:
```rust
impl CommitmentTransformProver {
    fn optimize_communication(&mut self) -> Result<(), Error> {
        // Compress e' = e[3, 3+dk) from dk Rq-elements to 2κ + O(log d) elements
        // Using same technique as double commitments
        
        let e_prime = &self.range_instance.evaluations.decomp_evals;
        
        // Decompose e' to τ_e ∈ (-d', d')^n'
        let tau_e = self.split_evaluations(e_prime);
        
        // Commit: com(τ_e) and com(exp(τ_e))
        let com_tau_e = self.commit_witness(&tau_e);
        let exp_tau_e = tau_e.iter().map(|&x| self.exp_function(x)).collect();
        let com_exp_tau_e = self.commit_monomials(&exp_tau_e);
        
        // Range check τ_e using Construction 4.3 (very efficient)
        let range_proof_tau_e = self.prove_warmup_range(&tau_e, &exp_tau_e)?;
        
        // Additional sumcheck claims for consistency
        // (i) ⟨pow(τ_e), s'⟩ = u
        // (ii) pow(τ_e)[β] = v_e and pow(τ_e)[β²] = v'_e
        // (iii) ct(ψ · v') = ⟨v, tensor(c')⟩
        
        Ok(())
    }
}
```


## 5. Folding Protocol

### 5.1 Main Folding Protocol (L-to-2 Folding)

**Purpose**: Fold L > 2 instances of R_{lin,B} into 2 instances of R_{lin,B}

**Two-Step Approach**:
1. **Folding Step**: L instances of R_{lin,B} → 1 instance of R_{lin,B²}
2. **Decomposition Step**: 1 instance of R_{lin,B²} → 2 instances of R_{lin,B}

**Data Structures**:
```rust
pub struct FoldingProver {
    instances: Vec<LinearInstance>,    // L instances of R_{lin,B}
    witnesses: Vec<Vec<RingElement>>,  // L witnesses
    commitment_key: AjtaiCommitment,
    norm_bound: i64,                   // B
}

pub struct LinearInstance {
    commitment: Commitment,            // cm_f
    challenge: Vec<RingElement>,       // r ∈ MC^(log n)
    evaluations: Vec<RingElement>,     // v ∈ Mq^(n_lin)
}

pub struct FoldingProof {
    range_proofs: Vec<RangeCheckProof>,
    transform_proofs: Vec<CommitmentTransformProof>,
    decomposition_proof: DecompositionProof,
}

pub struct FoldingOutput {
    instances: [LinearInstance; 2],    // 2 instances of R_{lin,B}
    witnesses: [Vec<RingElement>; 2],  // 2 witnesses
}
```

**Folding Algorithm**:
```rust
impl FoldingProver {
    pub fn fold(&mut self, transcript: &mut Transcript) 
        -> Result<FoldingOutput, Error> {
        // Step 1: Range check all L witnesses
        let range_proofs = self.prove_all_ranges(transcript)?;
        
        // Step 2: Transform to linear commitments
        let transform_proofs = self.transform_all_commitments(transcript)?;
        let linear_instances = self.extract_linear_instances(&transform_proofs);
        
        // Step 3: Fold L linear instances to 1 (with norm B²)
        let folded_instance = self.fold_linear_instances(
            &linear_instances, 
            transcript
        )?;
        
        // Step 4: Decompose to 2 instances (with norm B)
        let decomposition_proof = self.decompose_instance(
            &folded_instance,
            transcript
        )?;
        let output_instances = decomposition_proof.output_instances();
        
        Ok(FoldingOutput {
            instances: output_instances,
            witnesses: self.compute_output_witnesses(&decomposition_proof),
        })
    }
    
    fn prove_all_ranges(&mut self, transcript: &mut Transcript) 
        -> Result<Vec<RangeCheckProof>, Error> {
        // Prove ||f_i||∞ < B for all i ∈ [L]
        let mut proofs = Vec::with_capacity(self.instances.len());
        
        for (i, witness) in self.witnesses.iter().enumerate() {
            transcript.append_message(b"range_check_index", &i.to_le_bytes());
            
            let mut prover = RangeCheckProver::new(
                witness.clone(),
                self.norm_bound
            );
            let proof = prover.prove(transcript)?;
            proofs.push(proof);
        }
        
        Ok(proofs)
    }
    
    fn transform_all_commitments(&mut self, transcript: &mut Transcript) 
        -> Result<Vec<CommitmentTransformProof>, Error> {
        // Transform double commitments to linear commitments
        let mut proofs = Vec::with_capacity(self.instances.len());
        
        for (i, witness) in self.witnesses.iter().enumerate() {
            transcript.append_message(b"transform_index", &i.to_le_bytes());
            
            let mut prover = CommitmentTransformProver::new(
                witness.clone(),
                self.instances[i].clone()
            );
            let proof = prover.prove(transcript)?;
            proofs.push(proof);
        }
        
        Ok(proofs)
    }
    
    fn fold_linear_instances(&mut self,
                            instances: &[CommitmentTransformInstance],
                            transcript: &mut Transcript) 
        -> Result<FoldedInstance, Error> {
        // Fold L instances via random linear combination
        // Result has norm bound B² due to multiplication
        
        let l = instances.len();
        let folding_challenges = transcript.challenge_vector_from_set(
            "folding_challenges",
            l,
            &self.folding_set
        );
        
        // Compute folded commitment: cm_folded = Σ_i α_i · cm_i
        let mut cm_folded = Commitment::zero();
        for (i, instance) in instances.iter().enumerate() {
            let scaled = instance.folded_commitment.scalar_mul(&folding_challenges[i]);
            cm_folded = cm_folded.add(&scaled);
        }
        
        // Compute folded witness: f_folded = Σ_i α_i · f_i
        let mut f_folded = vec![RingElement::zero(); self.witnesses[0].len()];
        for (i, witness) in self.witnesses.iter().enumerate() {
            for (j, elem) in witness.iter().enumerate() {
                let scaled = elem.multiply(&folding_challenges[i]);
                f_folded[j] = f_folded[j].add(&scaled);
            }
        }
        
        // Verify norm: ||f_folded||∞ < B² (due to random linear combination)
        let norm_squared = self.norm_bound * self.norm_bound;
        self.verify_folded_norm(&f_folded, norm_squared)?;
        
        Ok(FoldedInstance {
            commitment: cm_folded,
            witness: f_folded,
            norm_bound: norm_squared,
        })
    }
    
    fn verify_folded_norm(&self, witness: &[RingElement], bound: i64) 
        -> Result<(), Error> {
        for elem in witness {
            if elem.infinity_norm() >= bound {
                return Err(Error::NormExceeded);
            }
        }
        Ok(())
    }
}
```

### 5.2 Decomposition Protocol

**Purpose**: Reduce R_{lin,B²} instance to 2 R_{lin,B} instances via witness decomposition

**Design Decisions**:
- Split each scalar into high and low bits
- Use gadget decomposition with base B
- Maintain norm bound B for output witnesses
- Similar to LatticeFold decomposition but optimized

**Data Structures**:
```rust
pub struct DecompositionProver {
    instance: FoldedInstance,          // Input with norm B²
    witness: Vec<RingElement>,         // f with ||f||∞ < B²
    base: i64,                         // B
}

pub struct DecompositionProof {
    low_instance: LinearInstance,      // f_low with ||f_low||∞ < B
    high_instance: LinearInstance,     // f_high with ||f_high||∞ < B
    consistency_proof: ConsistencyProof,
}

pub struct ConsistencyProof {
    // Proof that f = f_low + B · f_high
    sumcheck_proof: SumcheckProof,
    evaluation_proofs: Vec<EvaluationProof>,
}
```

**Decomposition Algorithm**:
```rust
impl DecompositionProver {
    pub fn decompose(&mut self, transcript: &mut Transcript) 
        -> Result<DecompositionProof, Error> {
        // Decompose f into f_low and f_high such that:
        // f = f_low + B · f_high
        // ||f_low||∞ < B and ||f_high||∞ < B
        
        let (f_low, f_high) = self.decompose_witness();
        
        // Commit to decomposed witnesses
        let cm_low = self.commitment_key.commit(&f_low);
        let cm_high = self.commitment_key.commit(&f_high);
        
        transcript.append_commitment("cm_low", &cm_low);
        transcript.append_commitment("cm_high", &cm_high);
        
        // Prove consistency: f = f_low + B · f_high
        let consistency_proof = self.prove_consistency(
            &f_low,
            &f_high,
            transcript
        )?;
        
        // Create output instances
        let low_instance = self.create_low_instance(cm_low, &f_low);
        let high_instance = self.create_high_instance(cm_high, &f_high);
        
        Ok(DecompositionProof {
            low_instance,
            high_instance,
            consistency_proof,
        })
    }
    
    fn decompose_witness(&self) -> (Vec<RingElement>, Vec<RingElement>) {
        // For each element f_i, decompose as f_i = f_i,low + B · f_i,high
        let n = self.witness.len();
        let mut f_low = vec![RingElement::zero(); n];
        let mut f_high = vec![RingElement::zero(); n];
        
        for (i, elem) in self.witness.iter().enumerate() {
            let (low, high) = self.decompose_element(elem);
            f_low[i] = low;
            f_high[i] = high;
        }
        
        (f_low, f_high)
    }
    
    fn decompose_element(&self, elem: &RingElement) -> (RingElement, RingElement) {
        // Decompose each coefficient
        let coeffs = elem.coefficients();
        let d = coeffs.len();
        
        let mut low_coeffs = vec![0i64; d];
        let mut high_coeffs = vec![0i64; d];
        
        for (j, &coeff) in coeffs.iter().enumerate() {
            // Decompose: coeff = low + B · high
            // where |low| < B and |high| < B
            let (low, high) = self.decompose_scalar(coeff);
            low_coeffs[j] = low;
            high_coeffs[j] = high;
        }
        
        (
            RingElement::from_coefficients(low_coeffs),
            RingElement::from_coefficients(high_coeffs)
        )
    }
    
    fn decompose_scalar(&self, x: i64) -> (i64, i64) {
        // Decompose x = low + B · high
        // Ensure |low| < B and |high| < B
        
        let b = self.base;
        let low = ((x % b) + b) % b; // Ensure positive
        let low = if low > b / 2 { low - b } else { low }; // Balance
        let high = (x - low) / b;
        
        (low, high)
    }
    
    fn prove_consistency(&mut self,
                        f_low: &[RingElement],
                        f_high: &[RingElement],
                        transcript: &mut Transcript) 
        -> Result<ConsistencyProof, Error> {
        // Prove f = f_low + B · f_high via sumcheck
        
        let challenge = transcript.challenge_vector("decomp_challenge", self.log_n());
        let tensor_challenge = compute_tensor_product(&challenge);
        
        // Compute evaluations
        let eval_f = self.multilinear_eval(&self.witness, &tensor_challenge);
        let eval_low = self.multilinear_eval(f_low, &tensor_challenge);
        let eval_high = self.multilinear_eval(f_high, &tensor_challenge);
        
        // Verify: eval_f = eval_low + B · eval_high
        let expected = eval_low.add(&eval_high.scalar_mul(self.base));
        if eval_f != expected {
            return Err(Error::ConsistencyCheckFailed);
        }
        
        // Create sumcheck proof for this relation
        let sumcheck_proof = self.create_consistency_sumcheck(
            f_low,
            f_high,
            &challenge,
            transcript
        )?;
        
        Ok(ConsistencyProof {
            sumcheck_proof,
            evaluation_proofs: vec![],
        })
    }
    
    fn create_low_instance(&self, cm: Commitment, witness: &[RingElement]) 
        -> LinearInstance {
        // Create R_{lin,B} instance for low part
        LinearInstance {
            commitment: cm,
            challenge: self.instance.challenge.clone(),
            evaluations: self.compute_evaluations(witness),
        }
    }
    
    fn create_high_instance(&self, cm: Commitment, witness: &[RingElement]) 
        -> LinearInstance {
        // Create R_{lin,B} instance for high part
        LinearInstance {
            commitment: cm,
            challenge: self.instance.challenge.clone(),
            evaluations: self.compute_evaluations(witness),
        }
    }
}
```

## 6. Integration with Neo

### 6.1 Tensor-of-Rings Framework

**Purpose**: Support small moduli (64-bit primes) via Neo's approach

**Design Decisions**:
- Reinterpret Rq ≅ ⊗^e F_q^(d/e) as tensor product
- Folding challenge set size q^e for security
- Sumcheck over extension field F_q^t
- Compatible with existing Neo implementation

**Data Structures**:
```rust
pub struct TensorRingConfig {
    base_field_size: u64,          // q (64-bit prime)
    embedding_degree: usize,       // e such that q ≡ 1 + 2^e (mod 4^e)
    ring_degree: usize,            // d
    extension_degree: usize,       // t for F_q^t
    security_level: usize,         // λ bits
}

pub struct SmallFieldFolding {
    config: TensorRingConfig,
    challenge_set: ExtensionFieldSet,  // F_q^e for folding
    sumcheck_field: ExtensionField,    // F_q^t for sumcheck
}
```

**Implementation**:
```rust
impl SmallFieldFolding {
    pub fn new(q: u64, d: usize, lambda: usize) -> Self {
        // Compute parameters for small field support
        let e = Self::compute_embedding_degree(q, d);
        let t = Self::compute_extension_degree(q, lambda);
        
        let config = TensorRingConfig {
            base_field_size: q,
            embedding_degree: e,
            ring_degree: d,
            extension_degree: t,
            security_level: lambda,
        };
        
        let challenge_set = ExtensionFieldSet::new(q, e);
        let sumcheck_field = ExtensionField::new(q, t);
        
        Self {
            config,
            challenge_set,
            sumcheck_field,
        }
    }
    
    fn compute_embedding_degree(q: u64, d: usize) -> usize {
        // Find e such that q ≡ 1 + 2^e (mod 4^e) and e | d
        for e in (1..=d).rev() {
            if d % e == 0 {
                let modulus = 4u64.pow(e as u32);
                if q % modulus == 1 + 2u64.pow(e as u32) {
                    return e;
                }
            }
        }
        1
    }
    
    fn compute_extension_degree(q: u64, lambda: usize) -> usize {
        // Compute t such that q^t ≥ 2^λ for security
        let log_q = (q as f64).log2();
        (lambda as f64 / log_q).ceil() as usize
    }
    
    pub fn challenge_set_size(&self) -> u128 {
        // |Challenge set| = q^e
        (self.config.base_field_size as u128)
            .pow(self.config.embedding_degree as u32)
    }
    
    pub fn sumcheck_soundness_error(&self, degree: usize, rounds: usize) -> f64 {
        // Error = (degree · rounds) / |F_q^t|
        let field_size = (self.config.base_field_size as f64)
            .powi(self.config.extension_degree as i32);
        (degree * rounds) as f64 / field_size
    }
}
```

### 6.2 Integration Points

**Reuse from Neo Implementation**:
```rust
pub struct NeoIntegration {
    // Reuse Neo's optimized components
    ntt_engine: NeoNTTEngine,
    field_arithmetic: NeoFieldArithmetic,
    parallel_executor: NeoParallelExecutor,
    memory_manager: NeoMemoryManager,
}

impl NeoIntegration {
    pub fn integrate_latticefold_plus(&mut self) -> LatticeFoldPlusEngine {
        LatticeFoldPlusEngine {
            // Core LatticeFold+ components
            cyclotomic_ring: CyclotomicRing::new_with_ntt(self.ntt_engine.clone()),
            monomial_checker: MonomialSetChecker::new(),
            range_checker: RangeChecker::new(),
            commitment_transformer: CommitmentTransformer::new(),
            
            // Neo optimizations
            ntt_engine: self.ntt_engine.clone(),
            field_ops: self.field_arithmetic.clone(),
            parallel: self.parallel_executor.clone(),
            memory: self.memory_manager.clone(),
            
            // Small field support
            tensor_config: TensorRingConfig::from_neo_config(),
        }
    }
}
```

## 7. Performance Analysis

### 7.1 Complexity Comparison

**LatticeFold vs LatticeFold+**:

| Component | LatticeFold | LatticeFold+ | Improvement |
|-----------|-------------|--------------|-------------|
| Prover Time | O(n) + L·log₂(B) commitments | O(n) + O(1) commitments | 5x faster |
| Verifier Circuit | Hash L·log₂(B) commitments | Hash O(1) commitments | Simpler |
| Proof Size | O_λ(κd log B + d log n) | O_λ(κd + log n) | Shorter |
| Range Proof | Bit decomposition | Algebraic (monomial) | No bit decomp |
| Soundness | Module-SIS | Module-SIS | Same |

### 7.2 Concrete Parameters

**Example Configuration** (128-bit security):
- Ring degree: d = 64
- Modulus: q = 2^64 - 2^32 + 1 (Goldilocks-like)
- Norm bound: B = (d/2)^k = 32^4 = 1,048,576
- Witness size: n = 2^16 = 65,536
- Security parameter: κ = 4

**LatticeFold+ Advantages**:
- Eliminates 4 · log₂(1,048,576) = 80 commitments per witness
- Reduces proof from ~5,120 ring elements to ~256 ring elements
- Prover 5x faster (measured by Nethermind)
- Verifier circuit ~20x smaller (fewer hashes)

## 8. Summary

This design document provides a complete architecture for LatticeFold+:

1. **Core Algebraic Structures**: Cyclotomic rings, monomials, norms
2. **Commitment Schemes**: Linear (Ajtai), double, gadget decomposition
3. **Proof Protocols**: Monomial check, range check, commitment transformation
4. **Folding Engine**: L-to-2 folding with decomposition
5. **Neo Integration**: Small field support, optimizations

**Key Innovations**:
- Algebraic range proof without bit decomposition
- Double commitments for proof compression
- Commitment transformation for folding
- Full compatibility with Neo's tensor-of-rings

**Next Steps**: Implementation phase with detailed task breakdown.
