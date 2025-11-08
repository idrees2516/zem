// Cyclotomic ring module

mod cyclotomic;
mod ntt;
mod rotation;
mod tensor;
mod hyperwolf_tensor;
mod integer_ring_map;
mod monomial;
mod projection;
mod decomposition;

pub use cyclotomic::{CyclotomicRing, RingElement};
pub use ntt::NTT;
pub use rotation::RotationMatrix;
pub use tensor::TensorElement;
pub use hyperwolf_tensor::WitnessTensor;
pub use integer_ring_map::IntegerRingMap;
pub use monomial::{MonomialSet, TablePolynomial, ExponentialMap};
pub use projection::{
    ProjectionMatrix, ProjectionParams, ProjectedWitness, ChiValue
};
pub use decomposition::{DecompositionParams, NormDecomposition, GadgetParams, GadgetDecomposition, decompose_vector};
