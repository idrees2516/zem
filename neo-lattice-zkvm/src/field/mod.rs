// Field arithmetic module

mod goldilocks;
mod m61;
mod extension;
mod symphony_extension;
mod traits;
mod simd;

pub use goldilocks::GoldilocksField;
pub use m61::{M61Field, Mersenne61Field};
pub use extension::ExtensionField;
pub use symphony_extension::{
    SymphonyExtensionParams, TowerField, 
    GoldilocksExtension, Mersenne61Extension
};
pub use traits::Field;
pub use simd::{batch_add_goldilocks, batch_mul_goldilocks, has_avx2};
