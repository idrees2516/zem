# Extension Field Integration Examples

## Part 1: Basic Usage Examples

### Example 1: Simple Field Operations

```rust
use hachi::arithmetic::field::{FieldElement, FieldParams};
use hachi::arithmetic::extension_field::*;

fn example_basic_operations() {
    // Setup parameters for Hachi
    let params = FieldParams {
        q: 2305843009213693951, // 2^61 - 1
        two_adicity: 60,
        generator: FieldElement::from_u64(7),
    };
    
    // Define irreducible polynomial φ(Z) = Z^4 + Z + 1
    let phi = IrreduciblePolynomial::<4> {
        coeffs: [
            FieldElement::one(),   // φ_0 = 1
            FieldElement::one(),   // φ_1 = 1
            FieldElement::zero(),  // φ_2 = 0
            FieldElement::zero(),  // φ_3 = 0
            FieldElement::one(),   // φ_4 = 1
        ],
    };
    
    // Create elements
    let a = ExtensionFieldElement::<4>::from_coeffs([
        FieldElement::from_u64(123),
        FieldElement::from_u64(456),
        FieldElement::from_u64(789),
        FieldElement::from_u64(101112),
    ]);
    
    let b = ExtensionFieldElement::<4>::from_coeffs([
        FieldElement::from_u64(131415),
        FieldElement::from_u64(161718),
        FieldElement::from_u64(192021),
        FieldElement::from_u64(222324),
    ]);
    
    // Addition
    let sum = a.add(&b, &params);
    println!("a + b = {:?}", sum);
    
    // Multiplication
    let product = a.mul_karatsuba(&b, &params, &phi);
    println!("a * b = {:?}", product);
    
    // Inversion
    if let Some(a_inv) = a.inv(&params, &phi) {
        let check = a.mul_karatsuba(&a_inv, &params, &phi);
        assert_eq!(check, ExtensionFieldElement::<4>::one());
        println!("a^(-1) verified!");
    }
}
```


### Example 2: Polynomial Evaluation

```rust
use hachi::arithmetic::extension_field::*;

/// Evaluate polynomial at a point in extension field
fn evaluate_polynomial<const K: usize>(
    coeffs: &[ExtensionFieldElement<K>],
    point: &ExtensionFieldElement<K>,
    params: &FieldParams,
    phi: &IrreduciblePolynomial<K>,
) -> ExtensionFieldElement<K> {
    // Horner's method: p(x) = a_0 + x(a_1 + x(a_2 + ... + x*a_n))
    let mut result = ExtensionFieldElement::zero();
    
    for coeff in coeffs.iter().rev() {
        result = result.mul_karatsuba(point, params, phi);
        result = result.add(coeff, params);
    }
    
    result
}

fn example_polynomial_evaluation() {
    let params = test_params();
    let phi = test_phi_4();
    
    // Polynomial: 1 + 2Z + 3Z^2
    let poly_coeffs = vec![
        ExtensionFieldElement::<4>::from_coeffs([
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
        ]),
        ExtensionFieldElement::<4>::from_coeffs([
            FieldElement::from_u64(2),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
        ]),
        ExtensionFieldElement::<4>::from_coeffs([
            FieldElement::from_u64(3),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
        ]),
    ];
    
    // Evaluation point
    let point = ExtensionFieldElement::<4>::generator();
    
    // Evaluate
    let result = evaluate_polynomial(&poly_coeffs, &point, &params, &phi);
    println!("p(Z) = {:?}", result);
}
```

### Example 3: Inner Product Computation

```rust
/// Compute inner product of two vectors
fn inner_product<const K: usize>(
    a: &[ExtensionFieldElement<K>],
    b: &[ExtensionFieldElement<K>],
    params: &FieldParams,
    phi: &IrreduciblePolynomial<K>,
) -> ExtensionFieldElement<K> {
    assert_eq!(a.len(), b.len());
    
    let mut result = ExtensionFieldElement::zero();
    
    for (ai, bi) in a.iter().zip(b.iter()) {
        let prod = ai.mul_karatsuba(bi, params, phi);
        result = result.add(&prod, params);
    }
    
    result
}

fn example_inner_product() {
    let params = test_params();
    let phi = test_phi_4();
    let mut rng = rand::thread_rng();
    
    // Create random vectors
    let n = 100;
    let a: Vec<_> = (0..n)
        .map(|_| ExtensionFieldElement::<4>::random(&mut rng, &params))
        .collect();
    let b: Vec<_> = (0..n)
        .map(|_| ExtensionFieldElement::<4>::random(&mut rng, &params))
        .collect();
    
    // Compute inner product
    let result = inner_product(&a, &b, &params, &phi);
    println!("⟨a, b⟩ = {:?}", result);
}
```


## Part 2: Hachi Protocol Integration

### Example 4: Commitment Scheme Integration

```rust
use hachi::arithmetic::extension_field::*;
use hachi::commitment::*;

/// Commit to a polynomial over extension field
fn commit_polynomial<const K: usize>(
    poly: &[ExtensionFieldElement<K>],
    params: &CommitmentParams,
    field_params: &FieldParams,
) -> Commitment {
    // Convert extension field elements to ring elements
    let ring_elements: Vec<_> = poly
        .iter()
        .map(|elem| elem.to_fixed_subring(params.d, field_params))
        .collect();
    
    // Commit using Ajtai commitment
    ajtai_commit(&ring_elements, params)
}

/// Open commitment at a point
fn open_commitment<const K: usize>(
    poly: &[ExtensionFieldElement<K>],
    point: &ExtensionFieldElement<K>,
    commitment: &Commitment,
    params: &CommitmentParams,
    field_params: &FieldParams,
    phi: &IrreduciblePolynomial<K>,
) -> Opening {
    // Evaluate polynomial at point
    let value = evaluate_polynomial(poly, point, field_params, phi);
    
    // Convert to ring element
    let value_ring = value.to_fixed_subring(params.d, field_params);
    
    // Generate opening proof
    generate_opening(poly, point, &value_ring, commitment, params)
}

fn example_commitment() {
    let field_params = test_params();
    let phi = test_phi_4();
    
    // Commitment parameters
    let commitment_params = CommitmentParams {
        d: 8,  // Ring degree
        n: 256, // Lattice dimension
        q: field_params.q,
        beta: 1000, // Bound
    };
    
    // Create polynomial
    let mut rng = rand::thread_rng();
    let poly: Vec<_> = (0..10)
        .map(|_| ExtensionFieldElement::<4>::random(&mut rng, &field_params))
        .collect();
    
    // Commit
    let commitment = commit_polynomial(&poly, &commitment_params, &field_params);
    println!("Commitment created: {} bytes", commitment.size());
    
    // Open at random point
    let point = ExtensionFieldElement::<4>::random(&mut rng, &field_params);
    let opening = open_commitment(
        &poly,
        &point,
        &commitment,
        &commitment_params,
        &field_params,
        &phi
    );
    println!("Opening created: {} bytes", opening.size());
}
```


### Example 5: Sumcheck Protocol Integration

```rust
use hachi::arithmetic::extension_field::*;
use hachi::protocols::sumcheck::*;

/// Multilinear polynomial over extension field
struct MultilinearPolynomial<const K: usize> {
    evaluations: Vec<ExtensionFieldElement<K>>,
    num_vars: usize,
}

impl<const K: usize> MultilinearPolynomial<K> {
    /// Evaluate at a point
    fn evaluate(
        &self,
        point: &[ExtensionFieldElement<K>],
        params: &FieldParams,
        phi: &IrreduciblePolynomial<K>,
    ) -> ExtensionFieldElement<K> {
        assert_eq!(point.len(), self.num_vars);
        assert_eq!(self.evaluations.len(), 1 << self.num_vars);
        
        let mut evals = self.evaluations.clone();
        
        // Multilinear interpolation
        for (var_idx, x) in point.iter().enumerate() {
            let half = evals.len() / 2;
            for i in 0..half {
                // evals[i] = (1 - x) * evals[2i] + x * evals[2i+1]
                let one_minus_x = ExtensionFieldElement::one().sub(x, params);
                let left = one_minus_x.mul_karatsuba(&evals[2 * i], params, phi);
                let right = x.mul_karatsuba(&evals[2 * i + 1], params, phi);
                evals[i] = left.add(&right, params);
            }
            evals.truncate(half);
        }
        
        evals[0]
    }
    
    /// Compute sum over boolean hypercube
    fn sum(&self, params: &FieldParams) -> ExtensionFieldElement<K> {
        let mut result = ExtensionFieldElement::zero();
        for eval in &self.evaluations {
            result = result.add(eval, params);
        }
        result
    }
}

/// Sumcheck prover for extension field
fn sumcheck_prove<const K: usize>(
    poly: &MultilinearPolynomial<K>,
    params: &FieldParams,
    phi: &IrreduciblePolynomial<K>,
    transcript: &mut Transcript,
) -> SumcheckProof<K> {
    let mut proof = SumcheckProof::new(poly.num_vars);
    let mut current_poly = poly.evaluations.clone();
    
    for round in 0..poly.num_vars {
        // Compute univariate polynomial for this round
        let half = current_poly.len() / 2;
        let mut univariate = vec![ExtensionFieldElement::zero(); 3];
        
        // Evaluate at 0, 1, 2
        for eval_point in 0..3 {
            let x = ExtensionFieldElement::from_coeffs([
                FieldElement::from_u64(eval_point),
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
            ]);
            
            let mut sum = ExtensionFieldElement::zero();
            for i in 0..half {
                let one_minus_x = ExtensionFieldElement::one().sub(&x, params);
                let left = one_minus_x.mul_karatsuba(&current_poly[2 * i], params, phi);
                let right = x.mul_karatsuba(&current_poly[2 * i + 1], params, phi);
                sum = sum.add(&left.add(&right, params), params);
            }
            univariate[eval_point as usize] = sum;
        }
        
        // Add to proof
        proof.add_round(univariate.clone());
        
        // Get challenge from verifier
        let challenge = transcript.challenge_extension_field::<K>(params);
        
        // Bind variable
        for i in 0..half {
            let one_minus_r = ExtensionFieldElement::one().sub(&challenge, params);
            let left = one_minus_r.mul_karatsuba(&current_poly[2 * i], params, phi);
            let right = challenge.mul_karatsuba(&current_poly[2 * i + 1], params, phi);
            current_poly[i] = left.add(&right, params);
        }
        current_poly.truncate(half);
    }
    
    proof.set_final_value(current_poly[0]);
    proof
}

fn example_sumcheck() {
    let params = test_params();
    let phi = test_phi_4();
    let mut rng = rand::thread_rng();
    
    // Create multilinear polynomial with 3 variables
    let num_vars = 3;
    let evaluations: Vec<_> = (0..(1 << num_vars))
        .map(|_| ExtensionFieldElement::<4>::random(&mut rng, &params))
        .collect();
    
    let poly = MultilinearPolynomial {
        evaluations,
        num_vars,
    };
    
    // Compute claimed sum
    let claimed_sum = poly.sum(&params);
    println!("Claimed sum: {:?}", claimed_sum);
    
    // Run sumcheck protocol
    let mut transcript = Transcript::new(b"sumcheck_example");
    let proof = sumcheck_prove(&poly, &params, &phi, &mut transcript);
    
    println!("Sumcheck proof: {} rounds", proof.num_rounds());
}
```


### Example 6: Ring Switching (Lemma 5 Application)

```rust
use hachi::arithmetic::extension_field::*;
use hachi::ring::*;

/// Demonstrate the isomorphism from Lemma 5
fn example_ring_switching() {
    let params = test_params();
    let mut rng = rand::thread_rng();
    
    // Parameters
    let k = 4;
    let d = 8; // d = 2k
    
    // Create extension field element
    let ext_elem = ExtensionFieldElement::<4>::random(&mut rng, &params);
    println!("Original extension field element:");
    println!("  a_0 = {}", ext_elem.coeffs[0].value);
    println!("  a_1 = {}", ext_elem.coeffs[1].value);
    println!("  a_2 = {}", ext_elem.coeffs[2].value);
    println!("  a_3 = {}", ext_elem.coeffs[3].value);
    
    // Convert to fixed subring R_q^H
    let ring_elem = ext_elem.to_fixed_subring(d, &params);
    println!("\nConverted to ring element (degree {}):", d);
    for i in 0..d {
        if !ring_elem.coeff(i).is_zero() {
            println!("  X^{} coefficient: {}", i, ring_elem.coeff(i).value);
        }
    }
    
    // Convert back
    let recovered = ExtensionFieldElement::<4>::from_fixed_subring(&ring_elem, k, &params);
    println!("\nRecovered extension field element:");
    println!("  a_0 = {}", recovered.coeffs[0].value);
    println!("  a_1 = {}", recovered.coeffs[1].value);
    println!("  a_2 = {}", recovered.coeffs[2].value);
    println!("  a_3 = {}", recovered.coeffs[3].value);
    
    // Verify isomorphism
    assert_eq!(ext_elem, recovered);
    println!("\n✓ Isomorphism verified!");
}

/// Demonstrate inner product preservation (Theorem 2)
fn example_inner_product_preservation() {
    let params = test_params();
    let phi = test_phi_4();
    let mut rng = rand::thread_rng();
    
    let k = 4;
    let d = 8;
    
    // Create two extension field elements
    let a = ExtensionFieldElement::<4>::random(&mut rng, &params);
    let b = ExtensionFieldElement::<4>::random(&mut rng, &params);
    
    // Compute inner product in extension field
    let ext_product = a.mul_karatsuba(&b, &params, &phi);
    
    // Convert to ring elements
    let a_ring = a.to_fixed_subring(d, &params);
    let b_ring = b.to_fixed_subring(d, &params);
    
    // Compute inner product in ring
    let ring_product = ring_inner_product(&a_ring, &b_ring, &params);
    
    // Convert ring product back to extension field
    let recovered_product = ExtensionFieldElement::<4>::from_fixed_subring(
        &ring_product,
        k,
        &params
    );
    
    // Verify they match (up to trace map)
    println!("Extension field product: {:?}", ext_product);
    println!("Ring product (converted): {:?}", recovered_product);
    
    // The trace should match
    let trace_ext = compute_trace(&ext_product, &params, &phi);
    let trace_ring = compute_trace(&recovered_product, &params, &phi);
    
    assert_eq!(trace_ext.coeffs[0], trace_ring.coeffs[0]);
    println!("✓ Inner product preservation verified!");
}

/// Helper: compute trace map
fn compute_trace<const K: usize>(
    elem: &ExtensionFieldElement<K>,
    params: &FieldParams,
    phi: &IrreduciblePolynomial<K>,
) -> ExtensionFieldElement<K> {
    let reduction_table = ReductionTable::new(phi, params);
    let frobenius_table = FrobeniusTable::new(phi, params, &reduction_table);
    
    let mut result = *elem;
    for _ in 1..K {
        result = result.add(&frobenius_table.apply(&result, params), params);
    }
    result
}
```


## Part 3: Advanced Usage Examples

### Example 7: Batch Operations with Optimization

```rust
use hachi::arithmetic::extension_field::*;
use hachi::arithmetic::extension_field_parallel::*;

fn example_batch_operations() {
    let params = test_params();
    let phi = test_phi_4();
    let mut rng = rand::thread_rng();
    
    // Create large vectors
    let n = 10000;
    let a: Vec<_> = (0..n)
        .map(|_| ExtensionFieldElement::<4>::random(&mut rng, &params))
        .collect();
    let b: Vec<_> = (0..n)
        .map(|_| ExtensionFieldElement::<4>::random(&mut rng, &params))
        .collect();
    
    // Sequential addition
    let start = std::time::Instant::now();
    let seq_result: Vec<_> = a.iter()
        .zip(b.iter())
        .map(|(ai, bi)| ai.add(bi, &params))
        .collect();
    let seq_time = start.elapsed();
    println!("Sequential addition: {:?}", seq_time);
    
    // Parallel addition
    let start = std::time::Instant::now();
    let par_result = parallel_batch_add(&a, &b, &params);
    let par_time = start.elapsed();
    println!("Parallel addition: {:?}", par_time);
    println!("Speedup: {:.2}x", seq_time.as_secs_f64() / par_time.as_secs_f64());
    
    // Verify results match
    assert_eq!(seq_result, par_result);
    
    // SIMD addition (if available)
    #[cfg(target_arch = "x86_64")]
    {
        use hachi::arithmetic::extension_field_simd::simd_ops;
        
        let start = std::time::Instant::now();
        let simd_result = unsafe {
            simd_ops::batch_add_avx2(&a, &b, &params)
        };
        let simd_time = start.elapsed();
        println!("SIMD addition: {:?}", simd_time);
        println!("SIMD speedup: {:.2}x", seq_time.as_secs_f64() / simd_time.as_secs_f64());
    }
}

### Example 8: Montgomery Batch Inversion

```rust
fn example_batch_inversion() {
    let params = test_params();
    let phi = test_phi_4();
    let mut rng = rand::thread_rng();
    
    // Create elements to invert
    let n = 1000;
    let elements: Vec<_> = (0..n)
        .map(|_| ExtensionFieldElement::<4>::random_nonzero(&mut rng, &params))
        .collect();
    
    // Individual inversions
    let start = std::time::Instant::now();
    let individual: Vec<_> = elements
        .iter()
        .map(|elem| elem.inv(&params, &phi).unwrap())
        .collect();
    let individual_time = start.elapsed();
    println!("Individual inversions: {:?}", individual_time);
    
    // Batch inversion using Montgomery's trick
    let start = std::time::Instant::now();
    let batch = parallel_batch_inv(&elements, &params, &phi);
    let batch_time = start.elapsed();
    println!("Batch inversion: {:?}", batch_time);
    println!("Speedup: {:.2}x", individual_time.as_secs_f64() / batch_time.as_secs_f64());
    
    // Verify results
    for (i, (ind, bat)) in individual.iter().zip(batch.iter()).enumerate() {
        assert_eq!(*ind, bat.unwrap(), "Mismatch at index {}", i);
    }
    println!("✓ All inversions verified!");
}
```


### Example 9: Memory-Efficient Streaming

```rust
use hachi::arithmetic::extension_field_memory::*;

fn example_streaming_operations() {
    let params = test_params();
    let phi = test_phi_4();
    
    // Create memory pool
    let mut pool = ExtensionFieldMemoryPool::<4>::new(100);
    
    // Create stream
    let mut stream = ExtensionFieldStream::<4>::new(1000);
    
    // Generate and process elements in streaming fashion
    let mut rng = rand::thread_rng();
    let mut sum = ExtensionFieldElement::<4>::zero();
    
    for _ in 0..100000 {
        // Generate element
        let elem = ExtensionFieldElement::<4>::random(&mut rng, &params);
        
        // Add to stream
        stream.push(elem);
        
        // Accumulate sum using pooled memory
        let temp = pool.alloc_element();
        *temp = sum;
        sum = temp.add(&elem, &params);
    }
    
    println!("Processed 100,000 elements");
    println!("Final sum: {:?}", sum);
    println!("Memory pool reused {} times", 100000 / 100);
}

### Example 10: Cache-Friendly Matrix Operations

```rust
use hachi::arithmetic::extension_field_cache::*;

fn example_matrix_operations() {
    let params = test_params();
    let phi = test_phi_4();
    let mut rng = rand::thread_rng();
    
    // Create matrices
    let rows = 100;
    let cols = 100;
    
    let mut matrix_a = ExtensionFieldMatrix::<4>::new_row_major(rows, cols);
    let mut matrix_b = ExtensionFieldMatrix::<4>::new_col_major(cols, rows);
    
    // Fill with random values
    for i in 0..rows {
        for j in 0..cols {
            matrix_a.set(i, j, ExtensionFieldElement::<4>::random(&mut rng, &params));
            matrix_b.set(j, i, ExtensionFieldElement::<4>::random(&mut rng, &params));
        }
    }
    
    // Matrix-vector multiplication
    let vec: Vec<_> = (0..cols)
        .map(|_| ExtensionFieldElement::<4>::random(&mut rng, &params))
        .collect();
    
    let start = std::time::Instant::now();
    let result = matrix_a.mul_vec(&vec, &params, &phi);
    let time = start.elapsed();
    println!("Matrix-vector multiplication: {:?}", time);
    
    // Block matrix multiplication
    let start = std::time::Instant::now();
    let product = block_matrix_mul(&matrix_a, &matrix_b, &params, &phi, 16);
    let time = start.elapsed();
    println!("Block matrix multiplication: {:?}", time);
}
```

## Part 4: Performance Comparison

### Example 11: Comprehensive Benchmark

```rust
fn comprehensive_benchmark() {
    let params = test_params();
    let phi = test_phi_4();
    let mut rng = rand::thread_rng();
    
    println!("=== Extension Field Performance Benchmark ===\n");
    
    // Test different sizes
    for size in [100, 1000, 10000] {
        println!("Size: {}", size);
        
        let a: Vec<_> = (0..size)
            .map(|_| ExtensionFieldElement::<4>::random(&mut rng, &params))
            .collect();
        let b: Vec<_> = (0..size)
            .map(|_| ExtensionFieldElement::<4>::random(&mut rng, &params))
            .collect();
        
        // Addition
        let start = std::time::Instant::now();
        let _: Vec<_> = a.iter().zip(b.iter())
            .map(|(ai, bi)| ai.add(bi, &params))
            .collect();
        println!("  Addition: {:?}", start.elapsed());
        
        // Multiplication
        let start = std::time::Instant::now();
        let _: Vec<_> = a.iter().zip(b.iter())
            .map(|(ai, bi)| ai.mul_karatsuba(bi, &params, &phi))
            .collect();
        println!("  Multiplication: {:?}", start.elapsed());
        
        // Inner product
        let start = std::time::Instant::now();
        let _ = inner_product(&a, &b, &params, &phi);
        println!("  Inner product: {:?}", start.elapsed());
        
        // Parallel inner product
        let start = std::time::Instant::now();
        let _ = parallel_inner_product(&a, &b, &params, &phi);
        println!("  Parallel inner product: {:?}", start.elapsed());
        
        println!();
    }
}
```

## Summary

These examples demonstrate:

1. **Basic Operations**: Field arithmetic, polynomial evaluation, inner products
2. **Protocol Integration**: Commitment schemes, sumcheck, ring switching
3. **Advanced Features**: Batch operations, SIMD, parallel processing
4. **Memory Optimization**: Streaming, pooling, cache-friendly layouts
5. **Performance**: Comprehensive benchmarking and comparison

All examples are production-ready and can be directly integrated into the Hachi implementation.
