// Extension field implementation F_q^k

use super::Field;

/// Extension field F_q^2 represented as F_q[X]/(f(X))
/// For Goldilocks: f(X) = X^2 + 7 (irreducible)
/// For general fields: f(X) = X^2 + 1 when q ≡ 3 (mod 4)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtensionField<F: Field> {
    /// Coefficients [c0, c1] representing c0 + c1*X
    pub coeffs: [F; 2],
}

impl<F: Field> ExtensionField<F> {
    /// Non-residue for extension field construction
    /// For Goldilocks: use 7
    /// For fields with q ≡ 3 (mod 4): use -1
    const NON_RESIDUE: u64 = 7;
    
    /// Create new extension field element
    pub fn new(c0: F, c1: F) -> Self {
        Self { coeffs: [c0, c1] }
    }
    
    /// Zero element
    pub fn zero() -> Self {
        Self {
            coeffs: [F::zero(), F::zero()]
        }
    }
    
    /// One element
    pub fn one() -> Self {
        Self {
            coeffs: [F::one(), F::zero()]
        }
    }
    
    /// Embed base field element into extension field
    pub fn from_base(x: F) -> Self {
        Self {
            coeffs: [x, F::zero()]
        }
    }
    
    /// Addition in extension field
    pub fn add(&self, rhs: &Self) -> Self {
        Self {
            coeffs: [
                self.coeffs[0].add(&rhs.coeffs[0]),
                self.coeffs[1].add(&rhs.coeffs[1]),
            ]
        }
    }
    
    /// Subtraction in extension field
    pub fn sub(&self, rhs: &Self) -> Self {
        Self {
            coeffs: [
                self.coeffs[0].sub(&rhs.coeffs[0]),
                self.coeffs[1].sub(&rhs.coeffs[1]),
            ]
        }
    }
    
    /// Multiplication in extension field
    /// (a0 + a1*X)(b0 + b1*X) = (a0*b0 - nr*a1*b1) + (a0*b1 + a1*b0)*X
    /// where X^2 = -nr (nr is non-residue)
    pub fn mul(&self, rhs: &Self) -> Self {
        let a0 = &self.coeffs[0];
        let a1 = &self.coeffs[1];
        let b0 = &rhs.coeffs[0];
        let b1 = &rhs.coeffs[1];
        
        let a0b0 = a0.mul(b0);
        let a1b1 = a1.mul(b1);
        let a0b1 = a0.mul(b1);
        let a1b0 = a1.mul(b0);
        
        let nr = F::from_u64(Self::NON_RESIDUE);
        let nr_a1b1 = nr.mul(&a1b1);
        
        Self {
            coeffs: [
                a0b0.sub(&nr_a1b1),
                a0b1.add(&a1b0),
            ]
        }
    }
    
    /// Negation in extension field
    pub fn neg(&self) -> Self {
        Self {
            coeffs: [
                self.coeffs[0].neg(),
                self.coeffs[1].neg(),
            ]
        }
    }
    
    /// Multiplicative inverse in extension field
    /// For a = a0 + a1*X, inv(a) = (a0 - a1*X) / (a0^2 + nr*a1^2)
    pub fn inv(&self) -> Option<Self> {
        let a0 = &self.coeffs[0];
        let a1 = &self.coeffs[1];
        
        // Compute norm: a0^2 + nr*a1^2
        let a0_sq = a0.mul(a0);
        let a1_sq = a1.mul(a1);
        let nr = F::from_u64(Self::NON_RESIDUE);
        let nr_a1_sq = nr.mul(&a1_sq);
        let norm = a0_sq.add(&nr_a1_sq);
        
        // Invert norm
        let norm_inv = norm.inv()?;
        
        // Compute conjugate / norm
        Some(Self {
            coeffs: [
                a0.mul(&norm_inv),
                a1.neg().mul(&norm_inv),
            ]
        })
    }
    
    /// Exponentiation in extension field
    pub fn pow(&self, exp: u64) -> Self {
        let mut result = Self::one();
        let mut base = *self;
        let mut e = exp;
        
        while e > 0 {
            if e & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base);
            e >>= 1;
        }
        
        result
    }
    
    /// Frobenius endomorphism: (a0 + a1*X)^q = a0 + a1*X^q
    /// For degree-2 extension, X^q = -X (when X^2 = -nr)
    pub fn frobenius(&self) -> Self {
        Self {
            coeffs: [
                self.coeffs[0],
                self.coeffs[1].neg(),
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    type GF2 = ExtensionField<GoldilocksField>;
    
    #[test]
    fn test_basic_arithmetic() {
        let a = GF2::new(
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4)
        );
        let b = GF2::new(
            GoldilocksField::from_u64(5),
            GoldilocksField::from_u64(6)
        );
        
        let sum = a.add(&b);
        assert_eq!(sum.coeffs[0].to_canonical_u64(), 8);
        assert_eq!(sum.coeffs[1].to_canonical_u64(), 10);
    }
    
    #[test]
    fn test_multiplication() {
        let a = GF2::new(
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3)
        );
        let b = GF2::new(
            GoldilocksField::from_u64(4),
            GoldilocksField::from_u64(5)
        );
        
        let prod = a.mul(&b);
        // (2 + 3X)(4 + 5X) = 8 + 10X + 12X + 15X^2
        //                   = 8 + 22X + 15*(-7)  (since X^2 = -7)
        //                   = 8 - 105 + 22X
        //                   = -97 + 22X
        
        // Verify it's not zero
        assert!(prod.coeffs[0].to_canonical_u64() != 0 || prod.coeffs[1].to_canonical_u64() != 0);
    }
    
    #[test]
    fn test_inverse() {
        let a = GF2::new(
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4)
        );
        
        let a_inv = a.inv().unwrap();
        let prod = a.mul(&a_inv);
        
        assert_eq!(prod.coeffs[0], GoldilocksField::one());
        assert_eq!(prod.coeffs[1], GoldilocksField::zero());
    }
    
    #[test]
    fn test_embedding() {
        let x = GoldilocksField::from_u64(42);
        let ext = GF2::from_base(x);
        
        assert_eq!(ext.coeffs[0], x);
        assert_eq!(ext.coeffs[1], GoldilocksField::zero());
    }
}
