# Symphony Lattice zkVM - Quick Start Guide

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd neo-lattice-zkvm

# Build the project
cargo build --release

# Run tests
cargo test --release

# Run integration tests
cargo test --release --test symphony_integration_tests
```

## Basic Usage

### 1. Simple Proof Generation

```rust
use neo_lattice_zkvm::snark::symphony::{SymphonySNARK, SymphonyParams};
use neo_lattice_zkvm::field::GoldilocksField;
use neo_lattice_zkvm::protocols::rok_traits::R1CSInstance;

type F = GoldilocksField;

fn main() -> Result<(), String> {
    // Setup with default post-quantum parameters
    let params = SymphonyParams::default_post_quantum();
    let snark = SymphonySNARK::<F>::setup(params)?;
    
    // Create R1CS instances (your application constraints)
    let instances = create_r1cs_instances();
    let witnesses = create_witnesses();
    
    // Generate proof
    println!("Generating proof...");
    let proof = snark.prove(&instances, &witnesses)?;
    println!("Proof size: {} bytes", proof.size());
    
    // Verify proof
    println!("Verifying proof...");
    let valid = snark.verify(&instances, &proof)?;
    println!("Proof valid: {}", valid);
    
    Ok(())
}
```

### 2. Parameter Selection

```rust
// Post-quantum security (128-bit, larger proofs)
let params = SymphonyParams::default_post_quantum();

// Classical security (128-bit, smaller proofs)
let params = SymphonyParams::default_classical();

// High throughput (maximum folding arity)
let params = SymphonyParams::high_throughput();

// Custom parameters
let mut params = SymphonyParams::default_post_quantum();
params.folding_arity = 8192;  // Adjust folding arity
params.use_streaming = true;   // Enable streaming prover
params.memory_budget = 2_000_000_000; // 2GB memory budget
```

### 3. Creating R1CS Instances

```rust
use neo_lattice_zkvm::protocols::rok_traits::{R1CSInstance, SparseMatrix};

// Example: x * y = z
fn create_multiplication_r1cs() -> R1CSInstance<F> {
    let num_constraints = 1;
    let num_variables = 3;
    
    // M1 selects x
    let mut m1 = SparseMatrix::new(num_constraints, num_variables);
    m1.add_entry(0, 0, F::one());
    
    // M2 selects y
    let mut m2 = SparseMatrix::new(num_constraints, num_variables);
    m2.add_entry(0, 1, F::one());
    
    // M3 selects z
    let mut m3 = SparseMatrix::new(num_constraints, num_variables);
    m3.add_entry(0, 2, F::one());
    
    R1CSInstance {
        num_constraints,
        num_variables,
        public_input: vec![F::from_u64(3), F::from_u64(4), F::from_u64(12)],
        matrices: (m1, m2, m3),
    }
}
```

### 4. Batch Proving

```rust
// Create multiple instances
let instances: Vec<R1CSInstance<F>> = (0..4096)
    .map(|_| create_r1cs_instance())
    .collect();

let witnesses: Vec<Vec<F>> = (0..4096)
    .map(|_| create_witness())
    .collect();

// Prove all at once with high-arity folding
let proof = snark.prove(&instances, &witnesses)?;
```

### 5. Streaming Prover (Memory-Efficient)

```rust
// Enable streaming for large batches
let mut params = SymphonyParams::default_post_quantum();
params.use_streaming = true;
params.memory_budget = 1_000_000_000; // 1GB

let snark = SymphonySNARK::<F>::setup(params)?;

// Prove with O(n) memory usage
let proof = snark.prove(&instances, &witnesses)?;
```

## Performance Estimation

```rust
// Estimate proof size
let proof_size = params.estimate_proof_size();
println!("Expected proof size: {} bytes ({:.2} KB)", 
         proof_size, proof_size as f64 / 1024.0);

// Estimate verification time
let verify_time = params.estimate_verification_time();
println!("Expected verification time: {:.2} ms", verify_time);

// Estimate prover complexity
let complexity = params.estimate_prover_complexity();
println!("Prover complexity: {:.2e} Rq-multiplications", complexity as f64);
```

## Common Patterns

### Pattern 1: zkVM Integration

```rust
struct ZkVM {
    snark: SymphonySNARK<F>,
}

impl ZkVM {
    fn new() -> Result<Self, String> {
        let params = SymphonyParams::default_post_quantum();
        let snark = SymphonySNARK::setup(params)?;
        Ok(Self { snark })
    }
    
    fn prove_program(&self, program: &Program) -> Result<Proof, String> {
        // Compile program to R1CS
        let r1cs = self.compile_to_r1cs(program)?;
        
        // Generate witness from execution trace
        let witness = self.execute_and_witness(program)?;
        
        // Generate proof
        self.snark.prove(&[r1cs], &[witness])
    }
    
    fn verify_program(&self, program: &Program, proof: &Proof) -> Result<bool, String> {
        let r1cs = self.compile_to_r1cs(program)?;
        self.snark.verify(&[r1cs], proof)
    }
}
```

### Pattern 2: Incremental Proving

```rust
struct IncrementalProver {
    snark: SymphonySNARK<F>,
    accumulated_instances: Vec<R1CSInstance<F>>,
    accumulated_witnesses: Vec<Vec<F>>,
}

impl IncrementalProver {
    fn add_statement(&mut self, instance: R1CSInstance<F>, witness: Vec<F>) {
        self.accumulated_instances.push(instance);
        self.accumulated_witnesses.push(witness);
    }
    
    fn finalize(&self) -> Result<Proof, String> {
        // Prove all accumulated statements at once
        self.snark.prove(&self.accumulated_instances, &self.accumulated_witnesses)
    }
}
```

### Pattern 3: Parallel Proof Generation

```rust
use rayon::prelude::*;

fn prove_parallel(
    snark: &SymphonySNARK<F>,
    batches: Vec<(Vec<R1CSInstance<F>>, Vec<Vec<F>>)>,
) -> Result<Vec<Proof>, String> {
    batches
        .par_iter()
        .map(|(instances, witnesses)| {
            snark.prove(instances, witnesses)
        })
        .collect()
}
```

## Testing

### Unit Tests

```bash
# Run all unit tests
cargo test --lib

# Run specific module tests
cargo test --lib ajtai
cargo test --lib sumcheck
cargo test --lib folding
```

### Integration Tests

```bash
# Run all integration tests
cargo test --test symphony_integration_tests

# Run specific integration test
cargo test --test symphony_integration_tests test_symphony_prove_verify_small_batch
```

### Benchmarks

```bash
# Run benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench folding_benchmark
```

## Troubleshooting

### Issue: Out of Memory

```rust
// Solution: Enable streaming prover
let mut params = SymphonyParams::default_post_quantum();
params.use_streaming = true;
params.memory_budget = 500_000_000; // Reduce memory budget
```

### Issue: Proof Too Large

```rust
// Solution: Use classical parameters or increase folding arity
let params = SymphonyParams::default_classical(); // Smaller proofs

// Or increase folding arity
let mut params = SymphonyParams::default_post_quantum();
params.folding_arity = 16384; // More instances per proof
```

### Issue: Verification Too Slow

```rust
// Solution: Reduce folding arity
let mut params = SymphonyParams::default_post_quantum();
params.folding_arity = 2048; // Faster verification
```

### Issue: Security Verification Failed

```rust
// Check parameters
if let Err(e) = params.verify_security() {
    println!("Security verification failed: {}", e);
    // Adjust parameters accordingly
}
```

## Advanced Features

### Custom Hash Functions

```rust
use neo_lattice_zkvm::fiat_shamir::hash_oracle::HashFunction;

let mut params = SymphonyParams::default_post_quantum();
params.hash_function = HashFunction::Poseidon; // SNARK-friendly
// or
params.hash_function = HashFunction::Blake3;   // Fast
// or
params.hash_function = HashFunction::Sha256;   // Standard
```

### Memory Budget Configuration

```rust
use neo_lattice_zkvm::protocols::streaming::StreamingConfig;

let config = StreamingConfig::with_memory_budget(2_000_000_000); // 2GB
println!("Chunk size: {}", config.chunk_size);
println!("Num passes: {}", config.num_passes);
```

### Custom Challenge Set

```rust
// Generate custom challenge set with specific properties
let ring = CyclotomicRing::<F>::new(64)?;
let challenge_set = generate_custom_challenge_set(&ring, 256)?;

// Verify operator norm
for elem in &challenge_set {
    assert!(elem.operator_norm() <= 15.0);
}
```

## Performance Tips

### 1. Batch Size Selection

```rust
// Small batches (< 1024): Fast verification, larger proof per instance
// Medium batches (4096-8192): Balanced
// Large batches (> 16384): Best amortization, slower verification

let optimal_batch_size = match use_case {
    UseCase::Interactive => 1024,
    UseCase::Balanced => 4096,
    UseCase::Throughput => 16384,
};
```

### 2. Memory Management

```rust
// For large batches, always use streaming
if instances.len() > 8192 {
    params.use_streaming = true;
}

// Adjust memory budget based on available RAM
let available_ram = get_available_ram();
params.memory_budget = (available_ram * 0.8) as usize; // Use 80% of available RAM
```

### 3. Parallelization

```rust
// Enable parallel processing
params.parallel = true;

// Set number of threads
rayon::ThreadPoolBuilder::new()
    .num_threads(num_cpus::get())
    .build_global()
    .unwrap();
```

## Examples

See the `examples/` directory for complete examples:

- `examples/simple_proof.rs` - Basic proof generation
- `examples/batch_proving.rs` - Batch proof generation
- `examples/streaming_prover.rs` - Memory-efficient proving
- `examples/zkvm_integration.rs` - zkVM integration
- `examples/ml_proof.rs` - ML inference proof

## API Reference

### Core Types

- `SymphonySNARK<F>` - Main SNARK system
- `SymphonyParams` - Configuration parameters
- `SymphonyProof<F>` - Proof structure
- `R1CSInstance<F>` - R1CS constraint system
- `CommitmentKey<F>` - Commitment scheme key

### Key Methods

- `SymphonySNARK::setup(params)` - Initialize system
- `snark.prove(instances, witnesses)` - Generate proof
- `snark.verify(instances, proof)` - Verify proof
- `params.verify_security()` - Validate parameters
- `params.estimate_proof_size()` - Estimate proof size

## Further Reading

- `ARCHITECTURE.md` - System architecture details
- `IMPLEMENTATION_SUMMARY.md` - Implementation details
- `implement todo.md` - Requirements specification
- Symphony paper - Theoretical foundation
- Neo paper - Commitment scheme details
- LatticeFold+ paper - Folding protocol details

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check existing documentation
- Review test cases for examples
- Consult the architecture document

## License

[Your License Here]
