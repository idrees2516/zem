// Symphony SNARK Benchmarks
// Comprehensive performance benchmarking suite

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use neo_lattice_zkvm::*;

fn benchmark_symphony_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("symphony_setup");
    
    for arity in [1024, 2048, 4096, 8192].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(arity), arity, |b, &arity| {
            b.iter(|| {
                let params = SymphonyParams {
                    folding_arity: arity,
                    ..SymphonyParams::default_post_quantum()
                };
                black_box(params.validate())
            });
        });
    }
    
    group.finish();
}

fn benchmark_proof_size_estimation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_size_estimation");
    
    for arity in [1024, 2048, 4096, 8192, 16384].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(arity), arity, |b, &arity| {
            let params = SymphonyParams {
                folding_arity: arity,
                ..SymphonyParams::default_post_quantum()
            };
            
            b.iter(|| {
                black_box(params.estimate_proof_size())
            });
        });
    }
    
    group.finish();
}

fn benchmark_hash_oracle(c: &mut Criterion) {
    use neo_lattice_zkvm::fiat_shamir::hash_oracle::{HashOracle, StandardHashOracle, HashFunction};
    
    let mut group = c.benchmark_group("hash_oracle");
    
    // Benchmark SHA-256
    group.bench_function("sha256_32bytes", |b| {
        b.iter(|| {
            let mut oracle = StandardHashOracle::new(HashFunction::Sha256);
            oracle.update(b"test message for benchmarking");
            black_box(oracle.finalize(32))
        });
    });
    
    // Benchmark BLAKE3
    group.bench_function("blake3_32bytes", |b| {
        b.iter(|| {
            let mut oracle = StandardHashOracle::new(HashFunction::Blake3);
            oracle.update(b"test message for benchmarking");
            black_box(oracle.finalize(32))
        });
    });
    
    // Benchmark BLAKE3 with larger output
    group.bench_function("blake3_256bytes", |b| {
        b.iter(|| {
            let mut oracle = StandardHashOracle::new(HashFunction::Blake3);
            oracle.update(b"test message for benchmarking");
            black_box(oracle.finalize(256))
        });
    });
    
    group.finish();
}

fn benchmark_challenge_derivation(c: &mut Criterion) {
    use neo_lattice_zkvm::fiat_shamir::hash_oracle::{HashOracle, StandardHashOracle, HashFunction};
    
    let mut group = c.benchmark_group("challenge_derivation");
    
    for num_challenges in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_challenges),
            num_challenges,
            |b, &num_challenges| {
                b.iter(|| {
                    let mut oracle = StandardHashOracle::new(HashFunction::Blake3);
                    oracle.update(b"initial state");
                    
                    for i in 0..num_challenges {
                        oracle.update(&i.to_le_bytes());
                        black_box(oracle.finalize(32));
                    }
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_parameter_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("parameter_validation");
    
    group.bench_function("validate_post_quantum", |b| {
        let params = SymphonyParams::default_post_quantum();
        b.iter(|| black_box(params.validate()));
    });
    
    group.bench_function("validate_classical", |b| {
        let params = SymphonyParams::default_classical();
        b.iter(|| black_box(params.validate()));
    });
    
    group.bench_function("validate_high_arity", |b| {
        let params = SymphonyParams::high_arity();
        b.iter(|| black_box(params.validate()));
    });
    
    group.finish();
}

fn benchmark_extraction_probability(c: &mut Criterion) {
    use neo_lattice_zkvm::snark::extraction::WitnessExtractor;
    use neo_lattice_zkvm::field::m61::M61;
    
    let mut group = c.benchmark_group("extraction_probability");
    
    for arity in [1024, 2048, 4096].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(arity), arity, |b, &arity| {
            let extractor = WitnessExtractor::<M61>::new(arity, vec![]);
            
            b.iter(|| {
                black_box(extractor.extraction_probability(0.9))
            });
        });
    }
    
    group.finish();
}

fn benchmark_knowledge_error(c: &mut Criterion) {
    use neo_lattice_zkvm::snark::extraction::knowledge_error_bound;
    
    let mut group = c.benchmark_group("knowledge_error");
    
    for arity in [1024, 2048, 4096, 8192].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(arity), arity, |b, &arity| {
            b.iter(|| {
                black_box(knowledge_error_bound(
                    2.0_f64.powi(-128),
                    arity,
                    1 << 20,
                ))
            });
        });
    }
    
    group.finish();
}

fn benchmark_cp_snark_relation(c: &mut Criterion) {
    use neo_lattice_zkvm::snark::cp_snark::CPSNARKRelation;
    use neo_lattice_zkvm::field::m61::M61;
    
    let mut group = c.benchmark_group("cp_snark_relation");
    
    for arity in [1024, 2048, 4096].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(arity), arity, |b, &arity| {
            b.iter(|| {
                black_box(CPSNARKRelation::<M61>::new(10, arity, 64))
            });
        });
    }
    
    group.finish();
}

fn benchmark_proof_size_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_size_scaling");
    
    let arities = vec![1024, 2048, 4096, 8192, 16384, 32768, 65536];
    
    for arity in arities.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(arity), arity, |b, &arity| {
            let params = SymphonyParams {
                folding_arity: arity,
                ..SymphonyParams::default_post_quantum()
            };
            
            b.iter(|| {
                black_box(params.estimate_proof_size())
            });
        });
    }
    
    group.finish();
}

fn benchmark_verification_time_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification_time_scaling");
    
    let arities = vec![1024, 2048, 4096, 8192, 16384, 32768, 65536];
    
    for arity in arities.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(arity), arity, |b, &arity| {
            let params = SymphonyParams {
                folding_arity: arity,
                ..SymphonyParams::default_post_quantum()
            };
            
            b.iter(|| {
                black_box(params.estimate_verification_time())
            });
        });
    }
    
    group.finish();
}

fn benchmark_prover_operations_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("prover_operations_scaling");
    
    let arities = vec![1024, 2048, 4096, 8192, 16384];
    
    for arity in arities.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(arity), arity, |b, &arity| {
            let params = SymphonyParams {
                folding_arity: arity,
                ..SymphonyParams::default_post_quantum()
            };
            
            b.iter(|| {
                black_box(params.estimate_prover_operations())
            });
        });
    }
    
    group.finish();
}

fn benchmark_streaming_config(c: &mut Criterion) {
    use neo_lattice_zkvm::protocols::streaming::StreamingConfig;
    
    let mut group = c.benchmark_group("streaming_config");
    
    group.bench_function("default", |b| {
        b.iter(|| black_box(StreamingConfig::default()));
    });
    
    group.bench_function("low_memory", |b| {
        b.iter(|| black_box(StreamingConfig::low_memory()));
    });
    
    group.bench_function("high_performance", |b| {
        b.iter(|| black_box(StreamingConfig::high_performance()));
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_symphony_setup,
    benchmark_proof_size_estimation,
    benchmark_hash_oracle,
    benchmark_challenge_derivation,
    benchmark_parameter_validation,
    benchmark_extraction_probability,
    benchmark_knowledge_error,
    benchmark_cp_snark_relation,
    benchmark_proof_size_scaling,
    benchmark_verification_time_scaling,
    benchmark_prover_operations_scaling,
    benchmark_streaming_config,
);

criterion_main!(benches);
