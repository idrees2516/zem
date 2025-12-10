// Field arithmetic module

mod goldilocks;
mod m61;
mod extension;
mod symphony_extension;
mod traits;
mod simd;
pub mod extension_framework;
pub mod babybear;
pub mod bn254;

pub use goldilocks::{GoldilocksField, Goldilocks};
pub use m61::{M61Field, Mersenne61Field};
pub use extension::ExtensionField;
pub use symphony_extension::{
    SymphonyExtensionParams, TowerField, 
    GoldilocksExtension, Mersenne61Extension
};
pub use traits::Field;
pub use simd::{batch_add_goldilocks, batch_mul_goldilocks, has_avx2};
pub use extension_framework::{
    ExtensionFieldElement, GenericExtensionField,
    M61ExtensionField2, M61ExtensionField4, M61ExtensionField8,
};
pub use babybear::{BabyBear, BabyBearField};
pub use bn254::{BN254, BN254Field};
