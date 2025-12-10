# Complete Sum-Check Based SNARK System - Design Document
## Integrated with Lattice-Based zkVM (Symphony + Neo + LatticeFold+ + HyperWolf)

## Overview

This design document specifies the complete integration of sum-check based SNARK techniques from "Sum-check Is All You Need" with the existing lattice-based zkVM infrastructure. The design creates a unified system where:

1. **Sum-check protocols** provide the core proof machinery for all constraint verification
2. **Lattice-based commitments** (Ajtai, Neo pay-per-bit, HyperWolf) provide post-quantum security
3. **Symphony's high-arity folding** compresses many statements without embedding hash functions
4. **Sparse sum-check algorithms** exploit structure in VM execution and CCS constraints
5. **Virtual polynomials** minimize commitment costs throughout the system
6. **Batch evaluation (Shout)** proves primitive instruction execution efficiently
7. **Memory checking (Twist)** handles register and RAM access with locality optimization
8. **Small-value preservation** accelerates both lattice operations and sum-check proving

### Key Design Principles

1. **Unified Sum-Check Foundation**: Every proof component uses sum-check as the core reduction
2. **Lattice-Native Integration**: All techniques adapted for cyclotomic rings and Module-SIS security
3. **Structure Exploitation**: Aggressive use of sparsity, small values, and repeated patterns
4. **Post-Quantum Security**: Maintain quantum resistance throughout the entire stack
5. **Streaming Compatibility**: Memory-efficient proving with controlled space usage
6. **Modular Architecture**: Clean interfaces enabling component substitution and testing

### System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                    Lattice-Based zkVM Application Layer                 │
│  (RISC-V Execution, Smart Contracts, Verifiable ML, Signatures)        │
└────────────────────────────────────────────────────────────────────────┘
                                    │
┌────────────────────────────────────────────────────────────────────────┐
│              Jolt-Style zkVM with Lattice Backend (NEW)                 │
│  ┌──────────────┬──────────────┬──────────────┬──────────────────┐   │
│  │ Fetch        │ Decode/Exec  │ Register     │ RAM Access       │   │
│  │ (Shout)      │ (Shout)      │ (Twist)      │ (Twist)          │   │
│  └──────────────┴──────────────┴──────────────┴──────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Constraint Checking (Spartan-style with Lattice Sum-Check)   │    │
│  └──────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────────┘
                                    │
┌────────────────────────────────────────────────────────────────────────┐
│         Shout & Twist Protocols (Lattice-Adapted) (NEW)                │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Shout: Batch Evaluation with Sparse Access Matrices          │    │
│  │ - One-hot encodings over Rq                                   │    │
│  │ - Prefix-suffix sum-check for streaming                       │    │
│  │ - Virtual polynomials for access matrix                       │    │
│  └──────────────────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Twist: Read-Write Memory with Increments                      │    │
│  │ - Dynamic function f(k,j) virtualization                      │    │
│  │ - Less-than predicate over extension field                    │    │
│  │ - Locality-aware optimization                                 │    │
│  └──────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────────┘
                                    │
┌────────────────────────────────────────────────────────────────────────┐
│              Symphony High-Arity Folding (EXISTING)                     │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Multi-Instance Folding (ℓ_np = 2^10 to 2^16)                 │    │
│  │ - Parallel Π_gr1cs with shared randomness                     │    │
│  │ - Merged sum-check claims (2ℓ_np → 2)                        │    │
│  │ - Random linear combination with β ← S^{ℓ_np}                │    │
│  └──────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────────┘
                                    │
┌────────────────────────────────────────────────────────────────────────┐
│         Sum-Check Protocol Layer (Lattice-Enhanced) (NEW)              │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Dense Sum-Check: O(N) prover for products of MLEs            │    │
│  │ Sparse Sum-Check: O(T + N^{1/c}) for sparsity T              │    │
│  │ Prefix-Suffix Algorithm: Streaming with O(√N) memory         │    │
│  │ Tensor-of-Rings Framework: E = K ⊗_Fq Rq                     │    │
│  └──────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────────┘
                                    │
┌────────────────────────────────────────────────────────────────────────┐
│         HyperWolf PCS with Sum-Check Integration (EXISTING+NEW)         │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ k-Round Witness Folding (Evaluation Proof)                    │    │
│  │ Guarded IPA (Exact ℓ₂-Norm Proof)                            │    │
│  │ Leveled Ajtai Commitment (Hierarchical Structure)            │    │
│  │ LaBRADOR Compression (O(log log log N) proofs)               │    │
│  └──────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────────┘
                                    │
┌────────────────────────────────────────────────────────────────────────┐
│         Neo Pay-Per-Bit + LatticeFold+ (EXISTING)                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Neo: Matrix commitments with bit-width scaling                │    │
│  │ LatticeFold+: Double commitments, range proofs                │    │
│  │ Monomial embedding for algebraic range proofs                 │    │
│  │ Random projection for approximate bounds                      │    │
│  └──────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────────┘
                                    │
┌────────────────────────────────────────────────────────────────────────┐
│              Lattice Primitives Layer (EXISTING)                        │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Cyclotomic Ring Rq = Zq[X]/(X^d + 1)                         │    │
│  │ Extension Field K = F_{q^t} for sum-check                    │    │
│  │ Tensor-of-Rings E = K ⊗_Fq Rq                                │    │
│  │ Module-SIS Security, NTT, Gadget Decomposition               │    │
│  └──────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────────┘
```

## Architecture

### Layer 1: Mathematical Foundation (Enhanced for Sum-Check)

#### 1.1 Multilinear Extension Framework

**Purpose**: Implement complete multilinear polynomial framework for sum-check protocols

**Components**:
```rust
/// Multilinear polynomial over extension field K
pub struct MultilinearPolynomial<K: ExtensionField> {
    /// Evaluations over Boolean hypercube {0,1}^n
    evaluations: Vec<K>,
    /// Number of variables
    num_vars: usize,
}

impl<K: ExtensionField> MultilinearPolynomial<K> {
    /// Create MLE from function evaluations
    pub fn from_evaluations(evals: Vec<K>) -> Self {
        assert!(evals.len().is_power_of_two());
        Self {
            evaluations: evals,
            num_vars: evals.len().trailing_zeros() as usize,
        }
    }
    
    /// Evaluate at point r ∈ K^n using Lagrange interpolation
    /// ã(r) = Σ_{x∈{0,1}^n} a(x) · eq̃(r,x)
    pub fn evaluate(&self, point: &[K]) -> K {
        assert_eq!(point.len(), self.num_vars);
        
        let mut result = K::zero();
        for (idx, &eval) in self.evaluations.iter().enumerate() {
            let x = Self::index_to_bits(idx, self.num_vars);
            let eq_val = Self::eq_polynomial(point, &x);
            result += eval * eq_val;
        }
        result
    }
    
    /// Equality polynomial: eq̃(r,x) = Π_{i=1}^n ((1-r_i)(1-x_i) + r_i·x_i)
    pub fn eq_polynomial(r: &[K], x: &[bool]) -> K {
        assert_eq!(r.len(), x.len());
        
        let mut result = K::one();
        for (r_i, &x_i) in r.iter().zip(x.iter()) {
            let term = if x_i {
                *r_i
            } else {
                K::one() - *r_i
            };
            result *= term;
        }
        result
    }
    
    /// Partial evaluation: fix first variable to value r_0
    /// Returns MLE over n-1 variables
    pub fn partial_eval(&self, r_0: K) -> Self {
        let half = self.evaluations.len() / 2;
        let mut new_evals = Vec::with_capacity(half);
        
        for i in 0..half {
            // p̃(r_0, x_2,...,x_n) = (1-r_0)·p̃(0,x_2,...,x_n) + r_0·p̃(1,x_2,...,x_n)
            let eval_0 = self.evaluations[i];
            let eval_1 = self.evaluations[i + half];
            new_evals.push((K::one() - r_0) * eval_0 + r_0 * eval_1);
        }
        
        Self {
            evaluations: new_evals,
            num_vars: self.num_vars - 1,
        }
    }
    
    /// Convert to tensor-of-rings representation for lattice operations
    pub fn to_tensor_of_rings(&self) -> Vec<TensorElement<K, Rq>> {
        self.evaluations.iter()
            .map(|&k_elem| TensorElement::from_k_scalar(k_elem))
            .collect()
    }
}
```

#### 1.2 Tensor-of-Rings Enhanced for Sum-Check

**Purpose**: Bridge between extension field sum-check and cyclotomic ring folding

**Components**:
```rust
/// Enhanced tensor E = K ⊗_Fq Rq with sum-check support
pub struct TensorOfRings<K: ExtensionField, R: CyclotomicRing> {
    /// Matrix representation over Zq^{t×d}
    matrix: Vec<Vec<Zq>>,
    /// Extension field degree t
    extension_degree: usize,
    /// Ring dimension d
    ring_dimension: usize,
}

impl<K, R> TensorOfRings<K, R> 
where 
    K: ExtensionField,
    R: CyclotomicRing,
{
    /// Interpret as K-vector space element for sum-check
    /// Returns [e_1, ..., e_d] ∈ K^d
    pub fn as_k_vector(&self) -> Vec<K> {
        let mut result = Vec::with_capacity(self.ring_dimension);
        
        for col in 0..self.ring_dimension {
            let mut k_elem = K::zero();
            for row in 0..self.extension_degree {
                let coeff = self.matrix[row][col];
                k_elem += K::from_base_field_element(coeff, row);
            }
            result.push(k_elem);
        }
        result
    }
    
    /// Interpret as Rq-module element for folding
    /// Returns (e'_1, ..., e'_t) ∈ Rq^t
    pub fn as_rq_module(&self) -> Vec<R> {
        let mut result = Vec::with_capacity(self.extension_degree);
        
        for row in 0..self.extension_degree {
            let ring_elem = R::from_coefficients(&self.matrix[row]);
            result.push(ring_elem);
        }
        result
    }
    
    /// K-scalar multiplication for sum-check operations
    pub fn k_scalar_mul(&self, scalar: K) -> Self {
        let scalar_coeffs = scalar.to_base_field_coefficients();
        let mut new_matrix = vec![vec![Zq::zero(); self.ring_dimension]; self.extension_degree];
        
        for i in 0..self.extension_degree {
            for j in 0..self.ring_dimension {
                for k in 0..self.extension_degree {
                    new_matrix[i][j] += scalar_coeffs[k] * self.matrix[(i + k) % self.extension_degree][j];
                }
            }
        }
        
        Self {
            matrix: new_matrix,
            extension_degree: self.extension_degree,
            ring_dimension: self.ring_dimension,
        }
    }
    
    /// Rq-scalar multiplication for folding operations
    pub fn rq_scalar_mul(&self, scalar: R) -> Self {
        let scalar_coeffs = scalar.coefficients();
        let mut new_matrix = vec![vec![Zq::zero(); self.ring_dimension]; self.extension_degree];
        
        for i in 0..self.extension_degree {
            for j in 0..self.ring_dimension {
                for k in 0..self.ring_dimension {
                    new_matrix[i][j] += self.matrix[i][(j + k) % self.ring_dimension] * scalar_coeffs[k];
                }
            }
        }
        
        Self {
            matrix: new_matrix,
            extension_degree: self.extension_degree,
            ring_dimension: self.ring_dimension,
        }
    }
}
```

### Layer 2: Core Sum-Check Protocol (Lattice-Adapted)

#### 2.1 Dense Sum-Check Prover

**Purpose**: Linear-time proving for products of multilinear polynomials over extension fields

**Components**:
```rust
/// Dense sum-check prover for g(x) = p̃(x) · q̃(x) over K
pub struct DenseSumCheckProver<K: ExtensionField> {
    /// Current round number
    round: usize,
    /// Arrays storing p̃ and q̃ evaluations
    p_evals: Vec<K>,
    q_evals: Vec<K>,
}

impl<K: ExtensionField> DenseSumCheckProver<K> {
    /// Initialize with full evaluations over {0,1}^n
    pub fn new(p: MultilinearPolynomial<K>, q: MultilinearPolynomial<K>) -> Self {
        assert_eq!(p.num_vars, q.num_vars);
        Self {
            round: 0,
            p_evals: p.evaluations,
            q_evals: q.evaluations,
        }
    }
    
    /// Compute round polynomial s_i(X) of degree 2
    /// s_i(X) = Σ_{x'∈{0,1}^{n-i}} p̃(r_1,...,r_{i-1},X,x') · q̃(r_1,...,r_{i-1},X,x')
    pub fn round_polynomial(&self) -> UnivariatePolynomial<K> {
        let n_remaining = self.p_evals.len();
        let half = n_remaining / 2;
        
        // Evaluate at X = 0, 1, 2
        let mut s_0 = K::zero();
        let mut s_1 = K::zero();
        let mut s_2 = K::zero();
        
        for i in 0..half {
            let p_0 = self.p_evals[i];
            let p_1 = self.p_evals[i + half];
            let q_0 = self.q_evals[i];
            let q_1 = self.q_evals[i + half];
            
            // s(0) = Σ p̃(0,x') · q̃(0,x')
            s_0 += p_0 * q_0;
            
            // s(1) = Σ p̃(1,x') · q̃(1,x')
            s_1 += p_1 * q_1;
            
            // s(2) = Σ p̃(2,x') · q̃(2,x') where p̃(2,x') = 2p̃(1,x') - p̃(0,x')
            let p_2 = K::from(2) * p_1 - p_0;
            let q_2 = K::from(2) * q_1 - q_0;
            s_2 += p_2 * q_2;
        }
        
        UnivariatePolynomial::from_evaluations(&[s_0, s_1, s_2])
    }
    
    /// Update state after receiving challenge r_i
    pub fn update(&mut self, challenge: K) {
        let n_remaining = self.p_evals.len();
        let half = n_remaining / 2;
        
        let mut new_p = Vec::with_capacity(half);
        let mut new_q = Vec::with_capacity(half);
        
        for i in 0..half {
            // p̃(r_i, x') = (1-r_i)·p̃(0,x') + r_i·p̃(1,x')
            let p_new = (K::one() - challenge) * self.p_evals[i] + challenge * self.p_evals[i + half];
            new_p.push(p_new);
            
            let q_new = (K::one() - challenge) * self.q_evals[i] + challenge * self.q_evals[i + half];
            new_q.push(q_new);
        }
        
        self.p_evals = new_p;
        self.q_evals = new_q;
        self.round += 1;
    }
    
    /// Get final evaluation g(r_1,...,r_n)
    pub fn final_evaluation(&self) -> K {
        assert_eq!(self.p_evals.len(), 1);
        assert_eq!(self.q_evals.len(), 1);
        self.p_evals[0] * self.q_evals[0]
    }
}
```

This is the beginning of a comprehensive design. Would you like me to continue with the remaining sections covering:
- Sparse sum-check with prefix-suffix algorithm
- Shout batch evaluation for lattice-based zkVM
- Twist memory checking
- Integration with Symphony folding
- HyperWolf PCS integration
- Complete zkVM architecture
- Performance analysis and optimizations?



#### 2.2 Sparse Sum-Check with Prefix-Suffix Algorithm

**Purpose**: Handle massive sums where most terms are zero, achieving O(T + N^{1/c}) time

**Components**:
```rust
/// Sparse sum-check for g(x) = p̃(x) · q̃(x) where p̃ has only T non-zero entries
pub struct SparseSumCheckProver<K: ExtensionField> {
    /// Non-zero entries of p̃ with their indices
    sparse_entries: Vec<(usize, K)>,
    /// Dense polynomial q̃ factored as q̃(i,j) = f̃(i) · h̃(j)
    f_evals: Vec<K>,
    h_evals: Vec<K>,
    /// Current stage (1 or 2)
    stage: usize,
    /// Arrays for current stage
    p_array: Vec<K>,
    q_array: Vec<K>,
}

impl<K: ExtensionField> SparseSumCheckProver<K> {
    /// Initialize with sparsity T and memory O(N^{1/c})
    pub fn new(
        sparse_p: Vec<(usize, K)>,
        f: Vec<K>,
        h: Vec<K>,
        c: usize,
    ) -> Self {
        let sqrt_n = f.len();
        assert_eq!(sqrt_n, h.len());
        
        // Stage 1 initialization: one streaming pass over non-zero terms
        let mut p_array = vec![K::zero(); sqrt_n];
        for &(idx, val) in &sparse_p {
            let (i, j) = Self::split_index(idx, sqrt_n);
            // P[i] = Σ_j p̃(i,j) · h̃(j)
            p_array[i] += val * h[j];
        }
        
        Self {
            sparse_entries: sparse_p,
            f_evals: f.clone(),
            h_evals: h,
            stage: 1,
            p_array,
            q_array: f, // Q[i] = f̃(i)
        }
    }
}
```


### Layer 3: Shout Protocol for Read-Only Memory (Lattice-Adapted)

#### 3.1 One-Hot Address Encoding

**Purpose**: Represent memory addresses as unit vectors for efficient sparse constraint systems

**Components**:
```rust
/// One-hot encoding with tensor product decomposition
pub struct OneHotAddress<K: ExtensionField> {
    /// Parameter d: number of chunks
    d: usize,
    /// Chunk size K^{1/d}
    chunk_size: usize,
    /// d one-hot vectors, each of length K^{1/d}
    chunks: Vec<Vec<K>>,
}

impl<K: ExtensionField> OneHotAddress<K> {
    /// Create d-dimensional one-hot encoding of address
    pub fn encode(address: usize, memory_size: usize, d: usize) -> Self {
        let chunk_size = (memory_size as f64).powf(1.0 / d as f64) as usize;
        let mut chunks = Vec::with_capacity(d);
        
        let mut remaining = address;
        for _ in 0..d {
            let mut chunk = vec![K::zero(); chunk_size];
            let chunk_idx = remaining % chunk_size;
            chunk[chunk_idx] = K::one();
            chunks.push(chunk);
            remaining /= chunk_size;
        }
        
        Self { d, chunk_size, chunks }
    }
    
    /// Verify this is valid one-hot encoding
    pub fn verify_one_hot(&self) -> bool {
        for chunk in &self.chunks {
            let sum: K = chunk.iter().copied().sum();
            if sum != K::one() {
                return false;
            }
            if !chunk.iter().all(|&x| x == K::zero() || x == K::one()) {
                return false;
            }
        }
        true
    }
    
    /// Compute tensor product to get full K-length vector
    pub fn to_full_vector(&self, memory_size: usize) -> Vec<K> {
        let mut result = vec![K::one()];
        
        for chunk in &self.chunks {
            let mut new_result = Vec::with_capacity(result.len() * chunk.len());
            for &r in &result {
                for &c in chunk {
                    new_result.push(r * c);
                }
            }
            result = new_result;
        }
        
        result.truncate(memory_size);
        result
    }
}
```


#### 3.2 Shout Core Protocol

**Purpose**: Batch evaluation argument for read-only memory using sparse sum-check

**Components**:
```rust
/// Shout protocol for T lookups into memory of size K
pub struct ShoutProtocol<K: ExtensionField, PCS: PolynomialCommitment<K>> {
    /// Memory size K
    memory_size: usize,
    /// Number of lookups T
    num_lookups: usize,
    /// Parameter d for tensor decomposition
    d: usize,
    /// Committed access matrices (d of them, each K^{1/d} × T)
    access_commitments: Vec<PCS::Commitment>,
    /// Lookup table (MLE-structured)
    table: MultilinearPolynomial<K>,
}

impl<K, PCS> ShoutProtocol<K, PCS>
where
    K: ExtensionField,
    PCS: PolynomialCommitment<K>,
{
    /// Prover commits to one-hot encoded addresses
    pub fn prover_commit(
        &mut self,
        addresses: &[usize],
        pcs: &PCS,
    ) -> Result<Vec<PCS::Commitment>, Error> {
        let chunk_size = (self.memory_size as f64).powf(1.0 / self.d as f64) as usize;
        let mut commitments = Vec::with_capacity(self.d);
        
        // For each dimension, create access matrix
        for dim in 0..self.d {
            let mut access_matrix = vec![vec![K::zero(); self.num_lookups]; chunk_size];
            
            for (j, &addr) in addresses.iter().enumerate() {
                let one_hot = OneHotAddress::encode(addr, self.memory_size, self.d);
                for (k, &val) in one_hot.chunks[dim].iter().enumerate() {
                    access_matrix[k][j] = val;
                }
            }
            
            // Flatten and commit
            let flat: Vec<K> = access_matrix.into_iter().flatten().collect();
            let mle = MultilinearPolynomial::from_evaluations(flat);
            let commitment = pcs.commit(&mle)?;
            commitments.push(commitment);
        }
        
        self.access_commitments = commitments.clone();
        Ok(commitments)
    }
}
```


    /// Core read-checking sum-check
    /// Proves: rv(r') = Σ_{k∈{0,1}^{log K}} ra(k,r') · Val(k)
    pub fn read_checking_sumcheck(
        &self,
        rcycle: &[K],
        prover_state: &mut SparseSumCheckProver<K>,
    ) -> Result<SumCheckProof<K>, Error> {
        let log_k = (self.memory_size as f64).log2() as usize;
        let mut transcript = Vec::new();
        
        for round in 0..log_k {
            // Compute round polynomial
            let round_poly = prover_state.round_polynomial();
            transcript.push(round_poly.clone());
            
            // Verifier samples challenge
            let challenge = K::random();
            prover_state.update(challenge);
        }
        
        // Final evaluation: ra(raddress, rcycle) · Val(raddress)
        let final_eval = prover_state.final_evaluation();
        
        Ok(SumCheckProof {
            round_polynomials: transcript,
            final_evaluation: final_eval,
        })
    }
    
    /// Booleanity check: verify ra(k,j) ∈ {0,1}
    pub fn booleanity_check(
        &self,
        access_mle: &MultilinearPolynomial<K>,
    ) -> Result<(), Error> {
        // Apply zero-check to: ra(k,j)² - ra(k,j) = 0
        let constraint = |k: &[K], j: &[K]| {
            let ra_val = access_mle.evaluate(&[k, j].concat());
            ra_val * ra_val - ra_val
        };
        
        // Use sparse sum-check since only T out of K·T entries are non-zero
        self.sparse_zero_check(constraint)
    }
    
    /// One-hot check: verify Σ_k ra(k,j) = 1 for all j
    pub fn one_hot_check(
        &self,
        access_mle: &MultilinearPolynomial<K>,
        rcycle: &[K],
    ) -> Result<(), Error> {
        // For non-binary fields, evaluate at (2^{-1}, ..., 2^{-1}, rcycle)
        if K::characteristic() > 2 {
            let half = K::from(2).inverse();
            let eval_point: Vec<K> = vec![half; (self.memory_size as f64).log2() as usize];
            let eval_point = [eval_point, rcycle.to_vec()].concat();
            
            let result = access_mle.evaluate(&eval_point);
            let expected = K::from(self.memory_size) * result;
            
            if expected != K::one() {
                return Err(Error::OneHotCheckFailed);
            }
        } else {
            // For binary fields, use sum-check directly
            self.hamming_weight_sumcheck(access_mle, rcycle)?;
        }
        
        Ok(())
    }
}
```


### Layer 4: Twist Protocol for Read-Write Memory

#### 4.1 Increment-Based Memory Representation

**Purpose**: Avoid K·T commitments by committing to increments instead of full values

**Components**:
```rust
/// Twist protocol for read-write memory with increments
pub struct TwistProtocol<K: ExtensionField, PCS: PolynomialCommitment<K>> {
    /// Memory size K
    memory_size: usize,
    /// Number of cycles T
    num_cycles: usize,
    /// Parameter d
    d: usize,
    /// Committed read addresses (d chunks)
    read_address_commitments: Vec<PCS::Commitment>,
    /// Committed write addresses (d chunks)
    write_address_commitments: Vec<PCS::Commitment>,
    /// Committed increments (only T non-zero values)
    increment_commitment: PCS::Commitment,
}

impl<K, PCS> TwistProtocol<K, PCS>
where
    K: ExtensionField,
    PCS: PolynomialCommitment<K>,
{
    /// Compute increment for cycle j
    /// Inc(k,j) = Val(k,j+1) - Val(k,j) = wa(k,j) · (wv(j) - Val(k,j))
    pub fn compute_increment(
        &self,
        k: usize,
        j: usize,
        write_address: &OneHotAddress<K>,
        write_value: K,
        current_value: K,
    ) -> K {
        let wa_kj = write_address.chunks.iter()
            .map(|chunk| chunk[k % chunk.len()])
            .product();
        
        wa_kj * (write_value - current_value)
    }
}
```


    /// Val-evaluation sum-check: compute Val(raddress, rcycle) from increments
    /// Val(raddress, rcycle) = Σ_{j'∈{0,1}^{log T}} Inc(raddress, j') · LT(j', rcycle)
    pub fn val_evaluation_sumcheck(
        &self,
        raddress: &[K],
        rcycle: &[K],
        increment_mle: &MultilinearPolynomial<K>,
    ) -> Result<K, Error> {
        let log_t = (self.num_cycles as f64).log2() as usize;
        let mut prover = DenseSumCheckProver::new(
            increment_mle.clone(),
            Self::less_than_mle(log_t),
        );
        
        // Run sum-check protocol
        let mut challenges = Vec::new();
        for _ in 0..log_t {
            let round_poly = prover.round_polynomial();
            let challenge = K::random();
            challenges.push(challenge);
            prover.update(challenge);
        }
        
        // Final evaluation
        let inc_eval = increment_mle.evaluate(&[raddress.to_vec(), challenges].concat());
        let lt_eval = Self::evaluate_less_than(rcycle, &challenges);
        
        Ok(inc_eval * lt_eval)
    }
    
    /// Less-than predicate: LT(j', j) = 1 iff j' < j
    /// Computable by verifier in O(log T) time
    pub fn less_than_mle(log_t: usize) -> MultilinearPolynomial<K> {
        let size = 1 << (2 * log_t);
        let mut evals = Vec::with_capacity(size);
        
        for idx in 0..size {
            let j_prime = idx >> log_t;
            let j = idx & ((1 << log_t) - 1);
            evals.push(if j_prime < j { K::one() } else { K::zero() });
        }
        
        MultilinearPolynomial::from_evaluations(evals)
    }
    
    /// Evaluate LT at random point (r', r)
    pub fn evaluate_less_than(r: &[K], r_prime: &[K]) -> K {
        assert_eq!(r.len(), r_prime.len());
        let n = r.len();
        
        let mut result = K::zero();
        let mut prefix_prod = K::one();
        
        for i in 0..n {
            // Contribution when bit i is first difference (r'_i < r_i)
            let term = prefix_prod * (K::one() - r_prime[i]) * r[i];
            result += term;
            
            // Update prefix: all previous bits equal
            prefix_prod *= r_prime[i] * r[i] + (K::one() - r_prime[i]) * (K::one() - r[i]);
        }
        
        result
    }
}
```


#### 4.2 Locality-Aware Twist Prover

**Purpose**: Achieve O(i) field multiplications for accesses to cells accessed 2^i steps prior

**Components**:
```rust
/// Locality-aware Twist prover that binds time variables first
pub struct LocalityAwareTwistProver<K: ExtensionField> {
    /// Access history: maps (cell, time) to last access time
    access_history: HashMap<usize, Vec<usize>>,
    /// Current sparsity (number of non-zeros)
    current_sparsity: usize,
    /// Round number
    round: usize,
}

impl<K: ExtensionField> LocalityAwareTwistProver<K> {
    /// Process memory operation with locality awareness
    pub fn process_operation(
        &mut self,
        cell: usize,
        time: usize,
        is_write: bool,
    ) -> usize {
        // Find last access to this cell
        let last_access = self.access_history
            .entry(cell)
            .or_insert_with(Vec::new)
            .last()
            .copied();
        
        let locality_cost = if let Some(last_time) = last_access {
            let delta = time - last_time;
            // Cost is O(log delta) for local accesses
            (delta as f64).log2().ceil() as usize
        } else {
            // First access: full O(log K) cost
            (self.memory_size as f64).log2() as usize
        };
        
        // Update access history
        self.access_history.get_mut(&cell).unwrap().push(time);
        
        locality_cost
    }
    
    /// Bind time variables first to enable coalescing
    pub fn bind_time_first_order(
        &mut self,
        log_k: usize,
        log_t: usize,
    ) -> Vec<usize> {
        // First log_t rounds bind time variables
        // This causes temporally-close accesses to coalesce quickly
        let mut order = (0..log_t).collect::<Vec<_>>();
        // Then log_k rounds bind memory variables
        order.extend(log_t..(log_t + log_k));
        order
    }
}
```


### Layer 5: Virtual Polynomials and Commitment Optimization

#### 5.1 Virtual Polynomial Framework

**Purpose**: Minimize prover commitments by expressing polynomials as low-degree functions of committed data

**Components**:
```rust
/// Virtual polynomial that is not directly committed
pub trait VirtualPolynomial<K: ExtensionField> {
    /// Express evaluation at point r via sum-check over committed polynomials
    fn evaluate_via_sumcheck(
        &self,
        point: &[K],
        committed_polys: &[MultilinearPolynomial<K>],
    ) -> Result<K, Error>;
    
    /// Get the sum-check claim for this virtual polynomial
    fn sumcheck_claim(&self, point: &[K]) -> SumCheckClaim<K>;
}

/// Read values as virtual polynomial in Shout
pub struct VirtualReadValues<K: ExtensionField> {
    /// Access matrix (committed)
    access_mle: MultilinearPolynomial<K>,
    /// Lookup table (public, MLE-structured)
    table_mle: MultilinearPolynomial<K>,
}

impl<K: ExtensionField> VirtualPolynomial<K> for VirtualReadValues<K> {
    fn evaluate_via_sumcheck(
        &self,
        rcycle: &[K],
        _committed: &[MultilinearPolynomial<K>],
    ) -> Result<K, Error> {
        // rv(rcycle) = Σ_{k∈{0,1}^{log K}} ra(k, rcycle) · Val(k)
        let log_k = self.table_mle.num_vars;
        let mut result = K::zero();
        
        for k_idx in 0..(1 << log_k) {
            let k_bits = Self::index_to_bits(k_idx, log_k);
            let ra_val = self.access_mle.evaluate(&[&k_bits[..], rcycle].concat());
            let table_val = self.table_mle.evaluate(&k_bits);
            result += ra_val * table_val;
        }
        
        Ok(result)
    }
    
    fn sumcheck_claim(&self, rcycle: &[K]) -> SumCheckClaim<K> {
        SumCheckClaim {
            polynomial: Box::new(|k: &[K]| {
                let ra_val = self.access_mle.evaluate(&[k, rcycle].concat());
                let table_val = self.table_mle.evaluate(k);
                ra_val * table_val
            }),
            num_vars: self.table_mle.num_vars,
        }
    }
}
```


/// Memory values as virtual polynomial in Twist
pub struct VirtualMemoryValues<K: ExtensionField> {
    /// Increments (committed)
    increment_mle: MultilinearPolynomial<K>,
    /// Write addresses (committed)
    write_address_mle: MultilinearPolynomial<K>,
}

impl<K: ExtensionField> VirtualPolynomial<K> for VirtualMemoryValues<K> {
    fn evaluate_via_sumcheck(
        &self,
        point: &[K], // (raddress, rcycle)
        _committed: &[MultilinearPolynomial<K>],
    ) -> Result<K, Error> {
        // Val(raddress, rcycle) = Σ_{j'} Inc(raddress, j') · LT(j', rcycle)
        let split = point.len() / 2;
        let raddress = &point[..split];
        let rcycle = &point[split..];
        
        let log_t = rcycle.len();
        let mut result = K::zero();
        
        for j_prime_idx in 0..(1 << log_t) {
            let j_prime_bits = Self::index_to_bits(j_prime_idx, log_t);
            let inc_val = self.increment_mle.evaluate(&[raddress, &j_prime_bits[..]].concat());
            let lt_val = TwistProtocol::<K, ()>::evaluate_less_than(rcycle, &j_prime_bits);
            result += inc_val * lt_val;
        }
        
        Ok(result)
    }
    
    fn sumcheck_claim(&self, point: &[K]) -> SumCheckClaim<K> {
        let split = point.len() / 2;
        let raddress = point[..split].to_vec();
        let rcycle = point[split..].to_vec();
        
        SumCheckClaim {
            polynomial: Box::new(move |j_prime: &[K]| {
                let inc_val = self.increment_mle.evaluate(&[&raddress[..], j_prime].concat());
                let lt_val = TwistProtocol::<K, ()>::evaluate_less_than(&rcycle, j_prime);
                inc_val * lt_val
            }),
            num_vars: rcycle.len(),
        }
    }
}

/// Address field elements as virtual polynomial
/// Converts one-hot encoding to single field element representation
pub struct VirtualAddressField<K: ExtensionField> {
    /// One-hot encoded addresses (committed, d chunks)
    one_hot_chunks: Vec<MultilinearPolynomial<K>>,
    /// Chunk size K^{1/d}
    chunk_size: usize,
}

impl<K: ExtensionField> VirtualPolynomial<K> for VirtualAddressField<K> {
    fn evaluate_via_sumcheck(
        &self,
        rcycle: &[K],
        _committed: &[MultilinearPolynomial<K>],
    ) -> Result<K, Error> {
        // raf(rcycle) = Σ_k (Σ_i 2^i · k_i) · Π_ℓ ra_ℓ(k_ℓ, rcycle)
        let log_chunk = (self.chunk_size as f64).log2() as usize;
        let d = self.one_hot_chunks.len();
        
        let mut result = K::zero();
        
        // Iterate over all possible addresses
        for k_idx in 0..(self.chunk_size.pow(d as u32)) {
            let mut address_value = K::zero();
            let mut product = K::one();
            
            // Decompose k_idx into d chunks
            let mut remaining = k_idx;
            for (chunk_idx, chunk_mle) in self.one_hot_chunks.iter().enumerate() {
                let k_i = remaining % self.chunk_size;
                remaining /= self.chunk_size;
                
                // Add contribution to address value
                let power = K::from(2).pow(chunk_idx * log_chunk);
                address_value += K::from(k_i) * power;
                
                // Multiply by one-hot indicator
                let k_i_bits = Self::index_to_bits(k_i, log_chunk);
                let indicator = chunk_mle.evaluate(&[&k_i_bits[..], rcycle].concat());
                product *= indicator;
            }
            
            result += address_value * product;
        }
        
        Ok(result)
    }
}
```


### Layer 6: Integration with Lattice-Based zkVM

#### 6.1 Jolt-Style zkVM Architecture with Lattice Backend

**Purpose**: Complete zkVM using Twist and Shout with lattice-based commitments

**Components**:
```rust
/// Lattice-based Jolt zkVM with Twist and Shout
pub struct LatticeJoltZkVM<K, R, PCS>
where
    K: ExtensionField,
    R: CyclotomicRing,
    PCS: PolynomialCommitment<K>,
{
    /// Number of registers (32 for RISC-V)
    num_registers: usize,
    /// RAM size
    ram_size: usize,
    /// Number of cycles per shard
    cycles_per_shard: usize,
    /// Shout instance for instruction fetch
    fetch_shout: ShoutProtocol<K, PCS>,
    /// Shout instance for instruction execution
    exec_shout: ShoutProtocol<K, PCS>,
    /// Twist instance for registers
    register_twist: TwistProtocol<K, PCS>,
    /// Twist instance for RAM
    ram_twist: TwistProtocol<K, PCS>,
    /// Constraint checker (Spartan-style)
    constraint_checker: ConstraintChecker<K, R, PCS>,
}

impl<K, R, PCS> LatticeJoltZkVM<K, R, PCS>
where
    K: ExtensionField,
    R: CyclotomicRing,
    PCS: PolynomialCommitment<K>,
{
    /// Initialize zkVM for RISC-V
    pub fn new_riscv(ram_size: usize, pcs: PCS) -> Self {
        Self {
            num_registers: 32,
            ram_size,
            cycles_per_shard: 1 << 20, // 1M cycles per shard
            fetch_shout: ShoutProtocol::new(
                1 << 20, // Program size up to 1M instructions
                1 << 20, // Cycles per shard
                1,       // d=1 for small program memory
                pcs.clone(),
            ),
            exec_shout: ShoutProtocol::new(
                1 << 16, // Instruction execution tables
                1 << 20, // Cycles per shard
                1,       // d=1 for small tables
                pcs.clone(),
            ),
            register_twist: TwistProtocol::new(
                32,      // 32 registers
                1 << 20, // Cycles per shard
                1,       // d=1 for tiny register file
                pcs.clone(),
            ),
            ram_twist: TwistProtocol::new(
                ram_size,
                1 << 20,
                4,       // d=4 for larger RAM
                pcs.clone(),
            ),
            constraint_checker: ConstraintChecker::new(pcs),
        }
    }
}
```


    /// Prove single cycle execution
    pub fn prove_cycle(
        &mut self,
        cycle: usize,
        instruction: Instruction,
        register_reads: &[usize; 2],
        register_write: usize,
    ) -> Result<CycleProof<K>, Error> {
        // 1. Fetch: prove instruction fetch via Shout
        let fetch_proof = self.fetch_shout.prove_lookup(
            cycle,
            instruction.address,
        )?;
        
        // 2. Decode/Execute: prove instruction execution via Shout
        let exec_proof = self.exec_shout.prove_batch_evaluation(
            &instruction.decompose_for_lookup(),
        )?;
        
        // 3. Register reads: prove via Twist
        let read_proofs = register_reads.iter()
            .map(|&reg| self.register_twist.prove_read(cycle, reg))
            .collect::<Result<Vec<_>, _>>()?;
        
        // 4. Register write: prove via Twist
        let write_proof = self.register_twist.prove_write(
            cycle,
            register_write,
            instruction.compute_result(),
        )?;
        
        // 5. RAM access (if load/store instruction)
        let ram_proof = if instruction.is_memory_op() {
            Some(self.ram_twist.prove_memory_op(
                cycle,
                instruction.memory_address(),
                instruction.is_load(),
            )?)
        } else {
            None
        };
        
        Ok(CycleProof {
            fetch_proof,
            exec_proof,
            read_proofs,
            write_proof,
            ram_proof,
        })
    }
    
    /// Prove entire shard (multiple cycles)
    pub fn prove_shard(
        &mut self,
        start_cycle: usize,
        instructions: &[Instruction],
    ) -> Result<ShardProof<K, R>, Error> {
        let mut cycle_proofs = Vec::new();
        
        for (offset, instruction) in instructions.iter().enumerate() {
            let cycle = start_cycle + offset;
            let proof = self.prove_cycle(
                cycle,
                *instruction,
                &instruction.source_registers(),
                instruction.dest_register(),
            )?;
            cycle_proofs.push(proof);
        }
        
        // Batch all proofs together
        let batched_proof = self.batch_cycle_proofs(cycle_proofs)?;
        
        // Apply Symphony folding to compress
        let folded_proof = self.apply_symphony_folding(batched_proof)?;
        
        Ok(folded_proof)
    }
}
```


#### 6.2 Symphony Integration for High-Arity Folding

**Purpose**: Compress many Twist/Shout instances using Symphony's parallel folding

**Components**:
```rust
/// Symphony folding for Twist and Shout proofs
pub struct SymphonyTwistShoutFolder<K, R>
where
    K: ExtensionField,
    R: CyclotomicRing,
{
    /// Number of instances to fold (ℓ_np)
    num_instances: usize,
    /// Shared randomness for folding
    beta: Vec<K>,
    /// Accumulated folded instance
    folded_instance: Option<FoldedInstance<K, R>>,
}

impl<K, R> SymphonyTwistShoutFolder<K, R>
where
    K: ExtensionField,
    R: CyclotomicRing,
{
    /// Fold multiple Shout instances
    pub fn fold_shout_instances(
        &mut self,
        instances: Vec<ShoutInstance<K>>,
    ) -> Result<FoldedInstance<K, R>, Error> {
        assert_eq!(instances.len(), self.num_instances);
        
        // Convert each Shout instance to CCS form
        let ccs_instances: Vec<_> = instances.iter()
            .map(|inst| self.shout_to_ccs(inst))
            .collect::<Result<Vec<_>, _>>()?;
        
        // Apply parallel Π_gr1cs with shared randomness
        let mut merged_claims = Vec::new();
        for (i, ccs) in ccs_instances.iter().enumerate() {
            let claim = self.compute_gr1cs_claim(ccs, self.beta[i])?;
            merged_claims.push(claim);
        }
        
        // Merge 2ℓ_np claims into 2 via random linear combination
        let final_claims = self.merge_claims(&merged_claims)?;
        
        // Convert back to tensor-of-rings for lattice operations
        let folded = self.claims_to_tensor_of_rings(final_claims)?;
        
        self.folded_instance = Some(folded.clone());
        Ok(folded)
    }
    
    /// Convert Shout instance to CCS (Customizable Constraint System)
    fn shout_to_ccs(&self, shout: &ShoutInstance<K>) -> Result<CCSInstance<K>, Error> {
        // Shout constraints are rank-d products
        // Convert to CCS matrices M_0, ..., M_{d-1}
        let matrices = self.build_shout_matrices(shout)?;
        
        Ok(CCSInstance {
            matrices,
            witness: shout.witness.clone(),
            public_input: shout.public_input.clone(),
        })
    }
}
```


### Layer 7: HyperWolf PCS Integration

#### 7.1 Lattice Commitment for Twist and Shout

**Purpose**: Provide post-quantum polynomial commitments for all Twist/Shout polynomials

**Components**:
```rust
/// HyperWolf commitment scheme adapted for Twist and Shout
pub struct HyperWolfTwistShout<R: CyclotomicRing> {
    /// Leveled Ajtai commitment parameters
    ajtai_params: AjtaiParams<R>,
    /// Guarded IPA parameters
    ipa_params: GuardedIPAParams<R>,
    /// LaBRADOR compression parameters
    labrador_params: LabradorParams,
}

impl<R: CyclotomicRing> HyperWolfTwistShout<R> {
    /// Commit to one-hot encoded address (mostly 0s)
    pub fn commit_one_hot_address(
        &self,
        address: &OneHotAddress<ExtensionField>,
    ) -> Result<Commitment<R>, Error> {
        // Exploit that most entries are 0
        // Only commit to the d positions that are 1
        let sparse_commitment = self.commit_sparse(
            &address.chunks,
            address.d,
        )?;
        
        Ok(sparse_commitment)
    }
    
    /// Commit to increments (sparse, small values)
    pub fn commit_increments(
        &self,
        increments: &[ExtensionField],
    ) -> Result<Commitment<R>, Error> {
        // Most increments are 0, non-zeros are small (32-bit values)
        // Use Neo pay-per-bit for small-value optimization
        let neo_commitment = self.neo_commit_small_values(increments)?;
        
        Ok(neo_commitment)
    }
    
    /// Evaluation proof for sparse polynomial
    pub fn prove_evaluation_sparse(
        &self,
        commitment: &Commitment<R>,
        point: &[ExtensionField],
        value: ExtensionField,
        sparse_poly: &SparsePolynomial<ExtensionField>,
    ) -> Result<EvaluationProof<R>, Error> {
        // Use k-round witness folding
        let folded_witness = self.fold_witness(sparse_poly, point)?;
        
        // Apply Guarded IPA for exact ℓ₂-norm proof
        let ipa_proof = self.guarded_ipa_prove(
            &folded_witness,
            commitment,
        )?;
        
        // Compress with LaBRADOR
        let compressed = self.labrador_compress(ipa_proof)?;
        
        Ok(compressed)
    }
}
```


## Performance Analysis

### Prover Costs

#### Twist for Registers (K=32, T=2^20)

**With d=1:**
- Commitments per cycle: 32 0s + 1 1 (read), 32 0s + 1 1 (write), 1 increment
- Field operations: O(32 + 2^20) ≈ O(2^20)
- Lattice operations: 2 group operations per cycle (for the two 1s)
- Total per cycle: ~2 lattice ops + ~1 field op

**Comparison to Spice:**
- Spice: 5 commitments per read (all small values) + 40 field ops
- Twist: 2 lattice ops + 1 field op
- Speedup: ~10-20× depending on lattice vs field operation costs

#### Shout for Instruction Execution (K=2^16, T=2^20)

**With d=1:**
- Commitments: 2^16 0s + 1 1 per lookup
- Field operations: O(2^16 + 5·2^20) ≈ O(5·2^20)
- Amortized per lookup: ~5 field ops

**Comparison to Lasso:**
- Lasso: 3 commitments per lookup + 12 field ops
- Shout: 1 lattice op + 5 field ops
- Speedup: ~2-3× for field work, commitment costs depend on lattice scheme

### Memory Usage

#### Streaming Prover with Prefix-Suffix

**For c=2 (square-root memory):**
- Stage 1: O(√N) = O(2^10) for N=2^20
- Stage 2: O(√N) = O(2^10)
- Total: ~2KB for arrays at any time

**For c=4:**
- Each stage: O(N^{1/4}) = O(2^5) for N=2^20
- Total: ~64 bytes for arrays

### Proof Sizes

**Per Cycle:**
- Twist (registers): d·log(K) + log(T) field elements ≈ 20 elements
- Shout (fetch): d·log(K) + log(T) field elements ≈ 20 elements
- Shout (exec): d·log(K) + log(T) field elements ≈ 20 elements
- Total: ~60 field elements per cycle

**After Symphony Folding:**
- Fold 2^10 cycles together
- Compressed to ~2 field elements per original cycle
- Final proof: ~2KB for 1M cycles

### Soundness Error

**Twist and Shout:**
- Error: log(K·T)/|F| ≈ 40/2^128 ≈ 2^{-122}
- Much better than offline memory checking: (K+T)/|F| ≈ 2^20/2^128 = 2^{-108}

**For 128-bit security:**
- Field size: 128-bit extension of 64-bit base
- Soundness: >120 bits even for T=2^40, K=2^30


## Data Models

### Core Data Structures

```rust
/// Multilinear polynomial over extension field
pub struct MultilinearPolynomial<K: ExtensionField> {
    pub evaluations: Vec<K>,
    pub num_vars: usize,
}

/// One-hot encoded address with tensor decomposition
pub struct OneHotAddress<K: ExtensionField> {
    pub d: usize,
    pub chunk_size: usize,
    pub chunks: Vec<Vec<K>>,
}

/// Shout protocol instance
pub struct ShoutInstance<K: ExtensionField> {
    pub memory_size: usize,
    pub num_lookups: usize,
    pub d: usize,
    pub access_matrices: Vec<Vec<Vec<K>>>,
    pub table: MultilinearPolynomial<K>,
    pub read_values: Option<Vec<K>>, // Virtual if None
}

/// Twist protocol instance
pub struct TwistInstance<K: ExtensionField> {
    pub memory_size: usize,
    pub num_cycles: usize,
    pub d: usize,
    pub read_addresses: Vec<Vec<Vec<K>>>,
    pub write_addresses: Vec<Vec<Vec<K>>>,
    pub increments: Vec<K>,
    pub write_values: Vec<K>,
}

/// Sum-check proof
pub struct SumCheckProof<K: ExtensionField> {
    pub round_polynomials: Vec<UnivariatePolynomial<K>>,
    pub final_evaluation: K,
}

/// Cycle proof for zkVM
pub struct CycleProof<K: ExtensionField> {
    pub fetch_proof: SumCheckProof<K>,
    pub exec_proof: SumCheckProof<K>,
    pub read_proofs: Vec<SumCheckProof<K>>,
    pub write_proof: SumCheckProof<K>,
    pub ram_proof: Option<SumCheckProof<K>>,
}

/// Folded instance after Symphony compression
pub struct FoldedInstance<K: ExtensionField, R: CyclotomicRing> {
    pub tensor_elements: Vec<TensorOfRings<K, R>>,
    pub claims: Vec<K>,
    pub randomness: Vec<K>,
}
```

## Error Handling

### Error Types

```rust
#[derive(Debug, Error)]
pub enum TwistShoutError {
    #[error("Invalid one-hot encoding: sum != 1")]
    InvalidOneHot,
    
    #[error("Booleanity check failed: value not in {{0,1}}")]
    BooleanityCheckFailed,
    
    #[error("Sum-check verification failed at round {round}")]
    SumCheckFailed { round: usize },
    
    #[error("Memory size {size} not compatible with parameter d={d}")]
    IncompatibleParameters { size: usize, d: usize },
    
    #[error("Commitment scheme error: {0}")]
    CommitmentError(String),
    
    #[error("Polynomial evaluation error: {0}")]
    EvaluationError(String),
    
    #[error("Folding error: {0}")]
    FoldingError(String),
}
```

## Testing Strategy

### Unit Tests

1. **Multilinear Extension Tests**
   - Verify MLE agrees with function on Boolean hypercube
   - Test partial evaluation correctness
   - Validate equality polynomial computation

2. **One-Hot Encoding Tests**
   - Verify tensor product decomposition
   - Test Booleanity and Hamming-weight-one checks
   - Validate address reconstruction

3. **Sum-Check Protocol Tests**
   - Test dense sum-check for products
   - Test sparse sum-check with various sparsities
   - Verify soundness error bounds

4. **Shout Protocol Tests**
   - Test read-checking sum-check
   - Verify virtual read values computation
   - Test with various memory sizes and d values

5. **Twist Protocol Tests**
   - Test increment computation
   - Verify Val-evaluation sum-check
   - Test locality-aware prover optimization
   - Validate less-than predicate

### Integration Tests

1. **zkVM Cycle Tests**
   - Prove single RISC-V instruction execution
   - Verify register reads and writes
   - Test RAM access for load/store

2. **Symphony Folding Tests**
   - Fold multiple Shout instances
   - Fold multiple Twist instances
   - Verify compression ratios

3. **End-to-End Tests**
   - Prove complete program execution
   - Verify proof composition
   - Test with real RISC-V binaries

### Performance Tests

1. **Prover Benchmarks**
   - Measure field operations per cycle
   - Measure lattice operations per cycle
   - Profile memory usage

2. **Verifier Benchmarks**
   - Measure verification time
   - Test proof size scaling

3. **Comparison Tests**
   - Compare to Spice baseline
   - Compare to Lasso baseline
   - Measure speedup factors

## Implementation Phases

### Phase 1: Core Sum-Check (Weeks 1-2)
- Implement multilinear polynomials over extension fields
- Implement dense sum-check prover and verifier
- Implement sparse sum-check with prefix-suffix
- Unit tests for all components

### Phase 2: Shout Protocol (Weeks 3-4)
- Implement one-hot encoding with tensor decomposition
- Implement Shout core protocol
- Implement Booleanity and one-hot checks
- Implement virtual read values
- Integration tests with mock commitments

### Phase 3: Twist Protocol (Weeks 5-6)
- Implement increment-based memory representation
- Implement Val-evaluation sum-check
- Implement read-checking and write-checking
- Implement locality-aware prover
- Integration tests with mock commitments

### Phase 4: Lattice Integration (Weeks 7-8)
- Integrate HyperWolf PCS
- Implement tensor-of-rings conversions
- Optimize for small values and sparsity
- Performance benchmarks

### Phase 5: zkVM Integration (Weeks 9-10)
- Implement Jolt-style zkVM architecture
- Integrate Twist for registers and RAM
- Integrate Shout for fetch and execution
- End-to-end tests with RISC-V programs

### Phase 6: Symphony Folding (Weeks 11-12)
- Implement CCS conversion for Twist/Shout
- Integrate parallel Π_gr1cs
- Implement claim merging
- Compression benchmarks

### Phase 7: Optimization and Production (Weeks 13-16)
- Profile and optimize hot paths
- Implement parallel proving
- Add comprehensive error handling
- Production hardening and documentation
