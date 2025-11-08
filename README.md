# latticezkvm

A production-ready lattice-based zkVM implementation featuring:

- **Neo Protocol**: Lattice-based folding scheme for CCS over small fields with pay-per-bit commitments
- **LatticeFold+**: Faster, simpler, shorter lattice-based folding
- **Symphony Integration**: Scalable SNARKs from lattice-based high-arity folding
- **HyperWolf PCS**: Lattice polynomial commitments with standard soundness
- **Rok and Roll**: Verifier-efficient random projection for compact lattice arguments

## Features

- Post-quantum secure zkVM based on lattice cryptography
- Efficient folding schemes for incremental verifiable computation
- Optimized polynomial commitment schemes
- Production-ready implementations with comprehensive testing

## Getting Started

```bash
cargo build --release
cargo test
cargo run --example hyperwolf_univariate
```

## Documentation

See the `docs.md` folder for detailed implementation documentation and status reports.

## License

MIT
