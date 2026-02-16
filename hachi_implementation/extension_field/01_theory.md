# Extension Field Theory - Complete Mathematical Foundation

## 1. Introduction to Extension Fields

### 1.1 What is an Extension Field?

An **extension field** F_{q^k} is a field that contains the base field F_q as a subfield. In Hachi, we use extension fields to:
- Achieve exponential challenge space size (|F_{q^k}| = q^k)
- Enable efficient sumcheck protocol over small fields
- Avoid expensive cyclotomic ring operations in verification

### 1.2 Why Extension Fields in Hachi?

**Problem**: Running sumcheck over R_q requires expensive ring operations
**Solution**: Use ring switching to lift to F_{q^k}[X], run sumcheck over F_{q^k}

**Benefits**:
- Verifier performs NO ring operations
- Sumcheck over small field elements (32k bits vs 32k·d bits)
- Asymptotic Õ(λ) speedup in verification

### 1.3 Construction Methods

There are multiple ways to construct F_{q^k}:

**Method 1: Polynomial Quotient Ring**
```
F_{q^k} = F_q[Z] / φ(Z)
```
where φ(Z) is an irreducible polynomial of degree k over F_q

**Method 2: Subfield of Cyclotomic Ring**
```
F_{q^k} ≅ R_q^H
```
where H = ⟨σ_{-1}, σ_{4k+1}⟩ is a subgroup of Galois automorphisms

**Hachi uses both**:
- Method 1 for general extension field arithmetic
- Method 2 for embedding into R_q (Lemma 5)

## 2. Polynomial Quotient Ring Construction

### 2.1 Irreducible Polynomials

An irreducible polynomial φ(Z) ∈ F_q[Z] of degree k cannot be factored into non-trivial polynomials over F_q.

**Example for k=2**:
```
φ(Z) = Z^2 + aZ + b
```
is irreducible if it has no roots in F_q

**Example for k=4**:
```
φ(Z) = Z^4 + Z + 1  (often irreducible for many primes q)
```

**Finding Irreducible Polynomials**:
```rust
fn find_irreducible_polynomial(q: u64, k: usize) -> Polynomial {
    // Method 1: Use known irreducible polynomials
    // For k=2: Z^2 + Z + 1 (if q ≡ 2 mod 3)
    // For k=4: Z^4 + Z + 1 (often works)
    
    // Method 2: Random search with irreducibility test
    loop {
        let candidate = random_polynomial(k);
        if is_irreducible(&candidate, q) {
            return candidate;
        }
    }
}

fn is_irreducible(poly: &Polynomial, q: u64) -> bool {
    // Test 1: No roots in F_q
    for a in 0..q {
        if poly.eval(a) == 0 {
            return false;
        }
    }
    
    // Test 2: Berlekamp's algorithm or other factorization test
    // ...
}
```

### 2.2 Element Representation

Elements of F_{q^k} are represented as polynomials of degree < k:

```
a ∈ F_{q^k} ⟺ a = a_0 + a_1·Z + a_2·Z^2 + ... + a_{k-1}·Z^{k-1}
```

where a_i ∈ F_q

**Storage**:
```rust
pub struct ExtensionFieldElement<const K: usize> {
    coeffs: [FieldElement; K],  // [a_0, a_1, ..., a_{k-1}]
}
```

**Example for k=4, q=13**:
```
a = 3 + 5Z + 7Z^2 + 11Z^3 ∈ F_{13^4}
Stored as: [3, 5, 7, 11]
```

### 2.3 Addition in Extension Fields

Addition is **coefficient-wise**:

```
(a_0 + a_1·Z + ... + a_{k-1}·Z^{k-1}) + (b_0 + b_1·Z + ... + b_{k-1}·Z^{k-1})
= (a_0+b_0) + (a_1+b_1)·Z + ... + (a_{k-1}+b_{k-1})·Z^{k-1}
```

**Algorithm**:
```rust
impl<const K: usize> ExtensionFieldElement<K> {
    pub fn add(&self, other: &Self, params: &FieldParams) -> Self {
        let mut result = [FieldElement::zero(); K];
        for i in 0..K {
            result[i] = self.coeffs[i].add(&other.coeffs[i], params);
        }
        ExtensionFieldElement { coeffs: result }
    }
}
```

**Complexity**: O(k) field additions

**Example**:
```
a = 3 + 5Z ∈ F_{13^2}
b = 7 + 11Z ∈ F_{13^2}
a + b = (3+7) + (5+11)Z = 10 + 16Z = 10 + 3Z (mod 13)
```

### 2.4 Multiplication in Extension Fields

Multiplication is **polynomial multiplication modulo φ(Z)**:

```
a·b = (a_0 + a_1·Z + ... + a_{k-1}·Z^{k-1}) · (b_0 + b_1·Z + ... + b_{k-1}·Z^{k-1}) mod φ(Z)
```

**Step 1**: Polynomial multiplication (degree up to 2k-2)
**Step 2**: Reduce modulo φ(Z) (back to degree < k)

**Naive Algorithm** (O(k^2)):
```rust
impl<const K: usize> ExtensionFieldElement<K> {
    pub fn mul_naive(&self, other: &Self, params: &FieldParams, phi: &Polynomial) -> Self {
        // Step 1: Polynomial multiplication
        let mut product = [FieldElement::zero(); 2*K];
        for i in 0..K {
            for j in 0..K {
                let term = self.coeffs[i].mul(&other.coeffs[j], params);
                product[i+j] = product[i+j].add(&term, params);
            }
        }
        
        // Step 2: Reduce modulo φ(Z)
        // Polynomial division: product = q·φ + r, return r
        let remainder = polynomial_mod(&product, phi, params);
        
        ExtensionFieldElement { coeffs: remainder }
    }
}
```

**Karatsuba Algorithm** (O(k^{log_2(3)}) ≈ O(k^{1.585})):

For k=2:
```
(a_0 + a_1·Z) · (b_0 + b_1·Z)
= a_0·b_0 + (a_0·b_1 + a_1·b_0)·Z + a_1·b_1·Z^2

Using Karatsuba:
Let m_0 = a_0·b_0
Let m_1 = a_1·b_1
Let m_2 = (a_0+a_1)·(b_0+b_1) - m_0 - m_1

Then: a·b = m_0 + m_2·Z + m_1·Z^2
```

**3 multiplications instead of 4!**

```rust
impl ExtensionFieldElement<2> {
    pub fn mul_karatsuba(&self, other: &Self, params: &FieldParams, phi: &Polynomial) -> Self {
        let a0 = &self.coeffs[0];
        let a1 = &self.coeffs[1];
        let b0 = &other.coeffs[0];
        let b1 = &other.coeffs[1];
        
        // Three multiplications
        let m0 = a0.mul(b0, params);
        let m1 = a1.mul(b1, params);
        let m2 = a0.add(a1, params).mul(&b0.add(b1, params), params)
                   .sub(&m0, params).sub(&m1, params);
        
        // Result before reduction: m0 + m2·Z + m1·Z^2
        // Reduce Z^2 using φ(Z) = Z^2 + φ_1·Z + φ_0
        // Z^2 = -φ_1·Z - φ_0
        
        let phi_0 = phi.coeff(0);
        let phi_1 = phi.coeff(1);
        
        let c0 = m0.sub(&m1.mul(&phi_0, params), params);
        let c1 = m2.sub(&m1.mul(&phi_1, params), params);
        
        ExtensionFieldElement { coeffs: [c0, c1] }
    }
}
```

**For k=4**: Recursive Karatsuba or specialized algorithms

### 2.5 Reduction Modulo Irreducible Polynomial

**General Method**: Polynomial long division

**Optimized Method**: Precompute reduction table

For φ(Z) = Z^k + φ_{k-1}·Z^{k-1} + ... + φ_1·Z + φ_0:

```
Z^k = -φ_{k-1}·Z^{k-1} - ... - φ_1·Z - φ_0
Z^{k+1} = Z·Z^k = -φ_{k-1}·Z^k - ... - φ_1·Z^2 - φ_0·Z
        = -φ_{k-1}·(-φ_{k-1}·Z^{k-1} - ... - φ_0) - ... - φ_0·Z
```

**Precompute**: Z^i mod φ(Z) for i = k, k+1, ..., 2k-2

```rust
struct ReductionTable<const K: usize> {
    // z_powers[i] = Z^{k+i} mod φ(Z) for i = 0..k-1
    z_powers: [[FieldElement; K]; K],
}

impl<const K: usize> ReductionTable<K> {
    pub fn new(phi: &Polynomial, params: &FieldParams) -> Self {
        let mut z_powers = [[FieldElement::zero(); K]; K];
        
        // Compute Z^k mod φ
        let mut current = [FieldElement::zero(); K];
        for i in 0..K {
            current[i] = phi.coeff(i).neg(params);
        }
        z_powers[0] = current;
        
        // Compute Z^{k+1}, Z^{k+2}, ..., Z^{2k-2} mod φ
        for i in 1..K {
            current = multiply_by_z(&current, &z_powers[0], params);
            z_powers[i] = current;
        }
        
        ReductionTable { z_powers }
    }
    
    pub fn reduce(&self, poly: &[FieldElement], params: &FieldParams) -> [FieldElement; K] {
        let mut result = [FieldElement::zero(); K];
        
        // Copy low-degree terms
        for i in 0..K {
            result[i] = poly[i];
        }
        
        // Reduce high-degree terms
        for i in K..poly.len() {
            let coeff = poly[i];
            let reduction = &self.z_powers[i - K];
            for j in 0..K {
                result[j] = result[j].add(&coeff.mul(&reduction[j], params), params);
            }
        }
        
        result
    }
}
```

## 3. Subfield Construction via Galois Automorphisms

### 3.1 Galois Automorphisms on R_q

Recall: R_q = Z_q[X]/(X^d + 1) where d = 2^α

**Galois automorphism** σ_i: R_q → R_q defined by X ↦ X^i for i ∈ Z_{2d}^×

**Properties**:
- σ_i(a + b) = σ_i(a) + σ_i(b)
- σ_i(a · b) = σ_i(a) · σ_i(b)
- σ_i ∘ σ_j = σ_{ij mod 2d}

**Example**:
```
σ_3(a_0 + a_1·X + a_2·X^2) = a_0 + a_1·X^3 + a_2·X^6
```

### 3.2 Fixed Subring R_q^H

For subgroup H ⊆ Aut(R_q):

```
R_q^H = {a ∈ R_q : ∀σ ∈ H, σ(a) = a}
```

Elements **fixed** by all automorphisms in H.

**Key Theorem (Lemma 5)**:
```
For q ≡ 5 (mod 8), k | d/2, and H = ⟨σ_{-1}, σ_{4k+1}⟩:
R_q^H ≅ F_{q^k}
```

### 3.3 Structure of R_q^H

Elements of R_q^H have special form:

```
a ∈ R_q^H ⟺ a = a_0 + ∑_{j=1}^{k-1} a_{k-j} · (X^{d·(k-j)/(2k)} - X^{d·(k+j)/(2k)})
```

**Degrees of freedom**: k coefficients (a_0, a_1, ..., a_{k-1}) ∈ Z_q

**Size**: |R_q^H| = q^k

**Example for k=2, d=8**:
```
a ∈ R_q^H ⟺ a = a_0 + a_1·(X^2 - X^6)
```

### 3.4 Isomorphism F_{q^k} ≅ R_q^H

**Forward map** φ: F_{q^k} → R_q^H:
```
φ(a_0 + a_1·Z + ... + a_{k-1}·Z^{k-1}) 
= a_0 + ∑_{j=1}^{k-1} a_{k-j} · (X^{d·(k-j)/(2k)} - X^{d·(k+j)/(2k)})
```

**Inverse map** φ^{-1}: R_q^H → F_{q^k}:
Extract coefficients from special form

**Properties**:
- φ(a + b) = φ(a) + φ(b)
- φ(a · b) = φ(a) · φ(b)
- φ is bijection

**Implementation**:
```rust
impl<const K: usize> ExtensionFieldElement<K> {
    /// Convert to fixed subring element
    pub fn to_fixed_subring(&self, d: usize) -> RingElement {
        let mut result = RingElement::zero(d);
        
        // Constant term
        result.set_coeff(0, self.coeffs[0]);
        
        // Higher terms
        for j in 1..K {
            let pos_idx = (d * (K - j)) / (2 * K);
            let neg_idx = (d * (K + j)) / (2 * K);
            
            result.set_coeff(pos_idx, self.coeffs[K - j]);
            result.set_coeff(neg_idx, self.coeffs[K - j].neg());
        }
        
        result
    }
    
    /// Convert from fixed subring element
    pub fn from_fixed_subring(ring_elem: &RingElement, k: usize) -> Self {
        let mut coeffs = [FieldElement::zero(); K];
        
        // Extract constant term
        coeffs[0] = ring_elem.coeff(0);
        
        // Extract higher terms
        for j in 1..k {
            let pos_idx = (ring_elem.degree() * (k - j)) / (2 * k);
            coeffs[k - j] = ring_elem.coeff(pos_idx);
        }
        
        ExtensionFieldElement { coeffs }
    }
}
```

## 4. Trace Map

### 4.1 Definition

For subgroup H ⊆ Aut(R_q):

```
Tr_H: R_q → R_q^H
Tr_H(a) = ∑_{σ ∈ H} σ(a)
```

**Properties**:
- Tr_H(a + b) = Tr_H(a) + Tr_H(b) (additive homomorphism)
- Tr_H(R_q^H) ⊆ R_q^H
- For a ∈ R_q^H: Tr_H(a) = |H| · a

### 4.2 Computing Trace for H = ⟨σ_{-1}, σ_{4k+1}⟩

```
Tr_H(a) = ∑_{σ ∈ H} σ(a)
        = ∑_{i ∈ ⟨4k+1⟩} (σ_i(a) + σ_{-i}(a))
```

where ⟨4k+1⟩ = {1, 4k+1, (4k+1)^2, ..., (4k+1)^{d/(2k)-1}}

**Algorithm**:
```rust
impl RingElement {
    pub fn trace(&self, k: usize) -> RingElement {
        let d = self.degree();
        let mut result = RingElement::zero(d);
        
        // Iterate over ⟨4k+1⟩
        let mut power = 1;
        for _ in 0..(d / (2*k)) {
            // Add σ_power(self) + σ_{-power}(self)
            result = result.add(&self.apply_automorphism(power));
            result = result.add(&self.apply_automorphism_neg(power));
            
            power = (power * (4*k + 1)) % (2*d);
        }
        
        result
    }
}
```

### 4.3 Trace and Inner Products (Theorem 2)

**Key Property**:
```
Tr_H(ψ(a) · σ_{-1}(ψ(b))) = (d/k) · ⟨a, b⟩
```

where ψ: (R_q^H)^{d/k} → R_q is the embedding map.

This is **crucial** for transforming inner products over F_{q^k} to relations over R_q!

## 5. Frobenius Automorphism

### 5.1 Definition

The **Frobenius automorphism** φ_q: F_{q^k} → F_{q^k} is defined by:

```
φ_q(a) = a^q
```

**Properties**:
- φ_q(a + b) = φ_q(a) + φ_q(b)
- φ_q(a · b) = φ_q(a) · φ_q(b)
- φ_q^k = identity (φ_q applied k times)
- Fixed points: {a ∈ F_{q^k} : φ_q(a) = a} = F_q

### 5.2 Computing Frobenius

**Method 1**: Direct exponentiation
```rust
impl<const K: usize> ExtensionFieldElement<K> {
    pub fn frobenius(&self, params: &FieldParams) -> Self {
        self.pow(params.q, params)
    }
}
```

**Method 2**: Precompute φ_q(Z^i) for i = 0..k-1

Since φ_q is linear:
```
φ_q(a_0 + a_1·Z + ... + a_{k-1}·Z^{k-1})
= a_0 + a_1·φ_q(Z) + ... + a_{k-1}·φ_q(Z^{k-1})
```

Precompute: φ_q(Z), φ_q(Z^2), ..., φ_q(Z^{k-1})

```rust
struct FrobeniusTable<const K: usize> {
    // frobenius_z[i] = Z^i raised to q-th power mod φ(Z)
    frobenius_z: [ExtensionFieldElement<K>; K],
}

impl<const K: usize> FrobeniusTable<K> {
    pub fn new(phi: &Polynomial, params: &FieldParams) -> Self {
        let mut frobenius_z = [ExtensionFieldElement::zero(); K];
        
        // Z^0 = 1
        frobenius_z[0] = ExtensionFieldElement::one();
        
        // Compute Z^q, Z^{2q}, ..., Z^{(k-1)q} mod φ
        let z = ExtensionFieldElement::generator(); // Z
        let mut current = z.pow(params.q, params, phi);
        frobenius_z[1] = current;
        
        for i in 2..K {
            current = current.mul(&frobenius_z[1], params, phi);
            frobenius_z[i] = current;
        }
        
        FrobeniusTable { frobenius_z }
    }
    
    pub fn apply(&self, elem: &ExtensionFieldElement<K>, params: &FieldParams) -> ExtensionFieldElement<K> {
        let mut result = ExtensionFieldElement::zero();
        
        for i in 0..K {
            let term = self.frobenius_z[i].mul_scalar(&elem.coeffs[i], params);
            result = result.add(&term, params);
        }
        
        result
    }
}
```

### 5.3 Applications

**Minimal polynomial computation**:
```
min_poly(a) = ∏_{i=0}^{k-1} (X - φ_q^i(a))
```

**Norm computation**:
```
Norm(a) = ∏_{i=0}^{k-1} φ_q^i(a) = a^{(q^k-1)/(q-1)}
```

**Trace computation**:
```
Trace(a) = ∑_{i=0}^{k-1} φ_q^i(a)
```

(This is different from Tr_H!)

## 6. Concrete Parameters for Hachi

### 6.1 Choice of k

**Security requirement**: |F_{q^k}| ≥ 2^λ

For λ = 128, q ≈ 2^32:
```
q^k ≥ 2^128
k · log_2(q) ≥ 128
k ≥ 128 / 32 = 4
```

**Hachi uses k = 4**

### 6.2 Irreducible Polynomial for k=4

Common choice:
```
φ(Z) = Z^4 + Z + 1
```

Verify irreducibility for q = 4294967197:
- No roots in F_q (check all q elements)
- No quadratic factors (more complex test)

### 6.3 Storage and Performance

**Element size**:
- F_q element: 32 bits
- F_{q^4} element: 4 × 32 = 128 bits

**Operation costs** (approximate):
- Addition: 4 field additions ≈ 20 ns
- Multiplication (Karatsuba): 9 field multiplications ≈ 100 ns
- Inversion: O(k^2) operations ≈ 5 μs

**Comparison with R_q** (d=1024):
- R_q element: 1024 × 32 = 32768 bits (256× larger!)
- R_q multiplication (NTT): ≈ 50 μs (500× slower!)

**This is why ring switching is so powerful!**
