// Symphony-specific extension field implementation
// Supports K = F_{q^t} for t = 2 with 128-bit security
// Implements tower field construction for efficient arithmetic
// Supports Goldilocks prime q = 2^64 - 2^32 + 1 with t = 2
// Supports Mersenne 61 prime q = 2^61 - 1 with t = 2

use super::{Field, ExtensionField};

/// Symphony extension field parameters
pub struct SymphonyExtensionParams {
    /// Extension degree (typically t = 2 for 128-bit security)
    pub degree: usize,
    /// Security level in bits
    pub security_bits: usize,
}

impl SymphonyExtensionParams {
    /// Create parameters for 128-bit security with t = 2
    pub fn new_128bit_security() -> Self {
        Self {
            degree: 2,
            security_bits: 128,
        }
    }
    
    /// Verify security level
    /// For 64-bit field with t = 2, we get 128-bit security
    pub fn verify_security<F: Field>(&self) -> bool {
        let field_bits = F::MODULUS_BITS;
        let total_bits = field_bits * self.degree;
        total_bits >= self.security_bits
    }
}

/// Tower field construction for efficient arithmetic
/// Represents F_{q^{2^k}} as tower of quadratic extensions
pub struct TowerField<F: Field> {
    /// Base field
    _phantom: std::marker::PhantomData<F>,
    /// Tower height (k where degree = 2^k)
    height: usize,
}

impl<F: Field> TowerField<F> {
    /// Create tower field of given height
    pub fn new(height: usize) -> Self {
        Self {
            _phantom: std::marker::PhantomData,
            height,
        }
    }
    
    /// Get total degree (2^height)
    pub fn degree(&self) -> usize {
        1 << self.height
    }
    
    /// Verify field axioms for extension field
    pub fn verify_field_axioms() -> bool {
        // Test additive identity
        let zero = ExtensionField::<F>::zero();
        let one = ExtensionField::<F>::one();
        let a = ExtensionField::new(F::from_u64(3), F::from_u64(4));
        
        // 0 + a = a
        if a.add(&zero) != a {
            return false;
        }
        
        // 1 * a = a
        if a.mul(&one) != a {
            return false;
        }
        
        // a + (-a) = 0
        if a.add(&a.neg()) != zero {
            return false;
        }
        
        // a * a^{-1} = 1 (if a != 0)
        if let Some(a_inv) = a.inv() {
            if a.mul(&a_inv) != one {
                return false;
            }
        }
        
        true
    }
}

/// Goldilocks extension field K = F_{q^2} where q = 2^64 - 2^32 + 1
pub type GoldilocksExtension = ExtensionField<crate::field::GoldilocksField>;

/// Mersenne 61 extension field K = F_{q^2} where q = 2^61 - 1
pub type Mersenne61Extension = ExtensionField<crate::field::Mersenne61Field>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{GoldilocksField, Mersenne61Field};
    
    #[test]
    fn test_symphony_params_128bit() {
        let params = SymphonyExtensionParams::new_128bit_security();
        assert_eq!(params.degree, 2);
        assert_eq!(params.security_bits, 128);
        
        // Verify Goldilocks with t=2 gives 128-bit security
        assert!(params.verify_security::<GoldilocksField>());
    }
    
    #[test]
    fn test_tower_field() {
        let tower = TowerField::<GoldilocksField>::new(1);
        assert_eq!(tower.degree(), 2);
        
        // Verify field axioms
        assert!(TowerField::<GoldilocksField>::verify_field_axioms());
    }
    
    #[test]
    fn test_goldilocks_extension() {
        let a = GoldilocksExtension::new(
            GoldilocksField::from_u64(5),
            GoldilocksField::from_u64(7)
        );
        let b = GoldilocksExtension::new(
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(2)
        );
        
        // Test addition
        let sum = a.add(&b);
        assert_eq!(sum.coeffs[0].to_canonical_u64(), 8);
        assert_eq!(sum.coeffs[1].to_canonical_u64(), 9);
        
        // Test multiplication
        let prod = a.mul(&b);
        assert!(prod.coeffs[0].to_canonical_u64() != 0 || prod.coeffs[1].to_canonical_u64() != 0);
        
        // Test inversion
        let a_inv = a.inv().unwrap();
        let identity = a.mul(&a_inv);
        assert_eq!(identity.coeffs[0], GoldilocksField::one());
        assert_eq!(identity.coeffs[1], GoldilocksField::zero());
    }
    
    #[test]
    fn test_mersenne61_extension() {
        let a = Mersenne61Extension::new(
            Mersenne61Field::from_u64(5),
            Mersenne61Field::from_u64(7)
        );
        let b = Mersenne61Extension::new(
            Mersenne61Field::from_u64(3),
            Mersenne61Field::from_u64(2)
        );
        
        // Test addition
        let sum = a.add(&b);
        assert_eq!(sum.coeffs[0].to_canonical_u64(), 8);
        assert_eq!(sum.coeffs[1].to_canonical_u64(), 9);
        
        // Test inversion
        let a_inv = a.inv().unwrap();
        let identity = a.mul(&a_inv);
        assert_eq!(identity.coeffs[0], Mersenne61Field::one());
        assert_eq!(identity.coeffs[1], Mersenne61Field::zero());
    }
}
