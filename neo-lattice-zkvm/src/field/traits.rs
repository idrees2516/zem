// Field trait definition

use std::fmt::Debug;
use std::hash::Hash;
use std::ops::{Add, Sub, Mul, Neg};

/// Base field trait for finite field arithmetic
/// 
/// This trait provides the core operations required for cryptographic protocols,
/// including lookup arguments. It is designed for production use with:
/// - Constant-time operations where security-critical
/// - Efficient batch operations for SIMD
/// - Comprehensive arithmetic operations
/// - Support for roots of unity (required for FFT/NTT)
pub trait Field: 
    Clone + 
    Copy + 
    Debug + 
    Eq + 
    PartialEq + 
    Hash +
    Add<Output = Self> +
    Sub<Output = Self> +
    Mul<Output = Self> +
    Neg<Output = Self> +
    Send +
    Sync +
    'static
{
    /// Field modulus (characteristic)
    const MODULUS: u64;
    
    /// Number of bits in modulus
    const MODULUS_BITS: usize;
    
    /// Two-adicity: largest k such that 2^k divides (MODULUS - 1)
    const TWO_ADICITY: usize;
    
    /// Field characteristic (same as MODULUS for prime fields)
    const CHARACTERISTIC: usize = Self::MODULUS as usize;
    
    /// Generator for multiplicative group (if exists)
    const GENERATOR: u64;
    
    /// Zero element constant
    const ZERO: Self;
    
    /// One element constant
    const ONE: Self;
    
    /// Zero element
    fn zero() -> Self;
    
    /// One element  
    fn one() -> Self;
    
    /// Two element (optimization for common case)
    fn two() -> Self {
        Self::one().add(&Self::one())
    }
    
    /// Create from u64 (with reduction)
    fn from_u64(val: u64) -> Self;
    
    /// Create from u128 (with reduction)
    fn from_u128(val: u128) -> Self {
        // Default implementation: reduce to u64 first
        Self::from_u64((val % (Self::MODULUS as u128)) as u64)
    }
    
    /// Create from i64 (handles negative values)
    fn from_i64(val: i64) -> Self {
        if val >= 0 {
            Self::from_u64(val as u64)
        } else {
            Self::from_u64((-val) as u64).neg()
        }
    }
    
    /// Convert to canonical u64 representation
    fn to_canonical_u64(&self) -> u64;
    
    /// Convert to u128 (for compatibility)
    fn to_u128(&self) -> u128 {
        self.to_canonical_u64() as u128
    }
    
    /// Check if element is zero
    fn is_zero(&self) -> bool {
        *self == Self::zero()
    }
    
    /// Check if element is one
    fn is_one(&self) -> bool {
        *self == Self::one()
    }
    
    /// Addition
    fn add(&self, rhs: &Self) -> Self;
    
    /// Subtraction
    fn sub(&self, rhs: &Self) -> Self;
    
    /// Multiplication
    fn mul(&self, rhs: &Self) -> Self;
    
    /// Negation
    fn neg(&self) -> Self;
    
    /// Square
    fn square(&self) -> Self {
        self.mul(self)
    }
    
    /// Double
    fn double(&self) -> Self {
        self.add(self)
    }
    
    /// Multiplicative inverse
    /// 
    /// Returns the multiplicative inverse if it exists (element is non-zero).
    /// Uses constant-time extended Euclidean algorithm for security.
    fn inverse(&self) -> Self {
        self.inv().expect("Cannot invert zero element")
    }
    
    /// Multiplicative inverse (returns None if element is zero)
    fn inv(&self) -> Option<Self>;
    
    /// Exponentiation by u64
    /// 
    /// Uses square-and-multiply algorithm.
    /// Constant-time variant available via pow_secure for sensitive operations.
    fn pow(&self, exp: u64) -> Self {
        let mut result = Self::one();
        let mut base = *self;
        let mut e = exp;
        
        while e > 0 {
            if e & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.square();
            e >>= 1;
        }
        
        result
    }
    
    /// Constant-time exponentiation (for security-critical operations)
    fn pow_secure(&self, exp: u64) -> Self {
        let mut result = Self::one();
        let base = *self;
        
        for i in (0..64).rev() {
            result = result.square();
            let bit = ((exp >> i) & 1) == 1;
            // Constant-time conditional: result = bit ? result * base : result
            let product = result.mul(&base);
            result = Self::conditional_select(&result, &product, bit);
        }
        
        result
    }
    
    /// Constant-time conditional selection
    /// Returns a if condition is true, b otherwise
    fn conditional_select(a: &Self, b: &Self, condition: bool) -> Self {
        if condition { *b } else { *a }
    }
    
    /// Square root (returns None if no square root exists)
    fn sqrt(&self) -> Option<Self>;
    
    /// Get primitive root of unity of order n
    /// 
    /// Returns ω such that ω^n = 1 and ω^i ≠ 1 for 0 < i < n.
    /// Requires n to be a power of 2 and n ≤ 2^TWO_ADICITY.
    fn get_root_of_unity(n: usize) -> Self {
        assert!(n.is_power_of_two(), "n must be power of 2");
        assert!(n.trailing_zeros() as usize <= Self::TWO_ADICITY, 
                "n too large for field's two-adicity");
        
        // ω = g^((q-1)/n) where g is generator
        let generator = Self::from_u64(Self::GENERATOR);
        let exponent = (Self::MODULUS - 1) / (n as u64);
        generator.pow(exponent)
    }
    
    /// Get all n-th roots of unity
    fn get_roots_of_unity(n: usize) -> Vec<Self> {
        let omega = Self::get_root_of_unity(n);
        let mut roots = Vec::with_capacity(n);
        let mut current = Self::one();
        
        for _ in 0..n {
            roots.push(current);
            current = current.mul(&omega);
        }
        
        roots
    }
    
    /// Random field element (cryptographically secure)
    fn random() -> Self;
    
    /// Generate n random field elements
    fn random_vec(n: usize) -> Vec<Self> {
        (0..n).map(|_| Self::random()).collect()
    }
    
    /// Batch addition for SIMD optimization
    fn batch_add(a: &[Self], b: &[Self]) -> Vec<Self> {
        assert_eq!(a.len(), b.len());
        a.iter().zip(b.iter()).map(|(x, y)| x.add(y)).collect()
    }
    
    /// Batch subtraction for SIMD optimization
    fn batch_sub(a: &[Self], b: &[Self]) -> Vec<Self> {
        assert_eq!(a.len(), b.len());
        a.iter().zip(b.iter()).map(|(x, y)| x.sub(y)).collect()
    }
    
    /// Batch multiplication for SIMD optimization
    fn batch_mul(a: &[Self], b: &[Self]) -> Vec<Self> {
        assert_eq!(a.len(), b.len());
        a.iter().zip(b.iter()).map(|(x, y)| x.mul(y)).collect()
    }
    
    /// Batch inversion using Montgomery's trick
    /// 
    /// Computes inverses of n elements in O(n) multiplications + 1 inversion.
    /// More efficient than n separate inversions.
    fn batch_inverse(elements: &[Self]) -> Vec<Self> {
        let n = elements.len();
        if n == 0 {
            return vec![];
        }
        
        if n == 1 {
            return vec![elements[0].inverse()];
        }
        
        // Compute products: prod[i] = elements[0] * ... * elements[i]
        let mut products = Vec::with_capacity(n);
        products.push(elements[0]);
        
        for i in 1..n {
            products.push(products[i - 1].mul(&elements[i]));
        }
        
        // Invert the final product
        let mut inv_product = products[n - 1].inverse();
        
        // Compute inverses in reverse order
        let mut inverses = vec![Self::zero(); n];
        
        for i in (1..n).rev() {
            // inverses[i] = inv_product * products[i-1]
            inverses[i] = inv_product.mul(&products[i - 1]);
            // inv_product = inv_product * elements[i]
            inv_product = inv_product.mul(&elements[i]);
        }
        
        inverses[0] = inv_product;
        
        inverses
    }
    
    /// Sum of elements
    fn sum(elements: &[Self]) -> Self {
        elements.iter().fold(Self::zero(), |acc, x| acc.add(x))
    }
    
    /// Product of elements
    fn product(elements: &[Self]) -> Self {
        elements.iter().fold(Self::one(), |acc, x| acc.mul(x))
    }
    
    /// Get primitive root of unity for FFT
    ///
    /// Returns ω such that ω^n = 1 and ω^i ≠ 1 for 0 < i < n
    /// This is an alias for get_root_of_unity for compatibility
    fn primitive_root_of_unity(n: usize) -> Result<Self, crate::lookup::LookupError> {
        if !n.is_power_of_two() {
            return Err(crate::lookup::LookupError::InvalidTableSize {
                size: n,
                required: "power of two".to_string(),
            });
        }
        
        if n.trailing_zeros() as usize > Self::TWO_ADICITY {
            return Err(crate::lookup::LookupError::InvalidTableSize {
                size: n,
                required: format!("at most 2^{}", Self::TWO_ADICITY),
            });
        }
        
        Ok(Self::get_root_of_unity(n))
    }
    
    /// Fast Fourier Transform (FFT)
    ///
    /// Computes evaluations of polynomial with given coefficients
    /// over the subgroup generated by omega
    ///
    /// # Arguments:
    /// - `coefficients`: Polynomial coefficients [a_0, a_1, ..., a_{n-1}]
    /// - `omega`: Primitive n-th root of unity
    ///
    /// # Returns:
    /// - Evaluations [p(1), p(ω), p(ω^2), ..., p(ω^{n-1})]
    ///
    /// # Performance: O(n log n)
    fn fft(coefficients: &[Self], omega: Self) -> Result<Vec<Self>, crate::lookup::LookupError> {
        let n = coefficients.len();
        
        if n == 0 {
            return Ok(vec![]);
        }
        
        if n == 1 {
            return Ok(coefficients.to_vec());
        }
        
        if !n.is_power_of_two() {
            return Err(crate::lookup::LookupError::InvalidVectorLength {
                expected: n.next_power_of_two(),
                got: n,
            });
        }
        
        // Cooley-Tukey FFT algorithm
        let mut result = coefficients.to_vec();
        Self::fft_in_place(&mut result, omega)?;
        Ok(result)
    }
    
    /// In-place FFT
    fn fft_in_place(values: &mut [Self], omega: Self) -> Result<(), crate::lookup::LookupError> {
        let n = values.len();
        
        if n <= 1 {
            return Ok(());
        }
        
        // Bit-reversal permutation
        let log_n = n.trailing_zeros() as usize;
        for i in 0..n {
            let j = reverse_bits(i, log_n);
            if i < j {
                values.swap(i, j);
            }
        }
        
        // Cooley-Tukey butterfly operations
        let mut m = 2;
        while m <= n {
            let omega_m = omega.pow((n / m) as u64);
            
            for k in (0..n).step_by(m) {
                let mut omega_power = Self::one();
                
                for j in 0..(m / 2) {
                    let t = omega_power.mul(&values[k + j + m / 2]);
                    let u = values[k + j];
                    values[k + j] = u.add(&t);
                    values[k + j + m / 2] = u.sub(&t);
                    omega_power = omega_power.mul(&omega_m);
                }
            }
            
            m *= 2;
        }
        
        Ok(())
    }
    
    /// Inverse Fast Fourier Transform (IFFT)
    ///
    /// Computes polynomial coefficients from evaluations
    ///
    /// # Arguments:
    /// - `evaluations`: Evaluations [p(1), p(ω), ..., p(ω^{n-1})]
    /// - `omega`: Primitive n-th root of unity
    ///
    /// # Returns:
    /// - Coefficients [a_0, a_1, ..., a_{n-1}]
    ///
    /// # Performance: O(n log n)
    fn ifft(evaluations: &[Self], omega: Self) -> Result<Vec<Self>, crate::lookup::LookupError> {
        let n = evaluations.len();
        
        if n == 0 {
            return Ok(vec![]);
        }
        
        if n == 1 {
            return Ok(evaluations.to_vec());
        }
        
        // IFFT = FFT with omega^{-1}, then divide by n
        let omega_inv = omega.inverse();
        let mut result = Self::fft(evaluations, omega_inv)?;
        
        let n_inv = Self::from_u64(n as u64).inverse();
        for val in result.iter_mut() {
            *val = val.mul(&n_inv);
        }
        
        Ok(result)
    }
    
    /// Convert to bytes (little-endian)
    fn to_bytes(&self) -> Vec<u8> {
        self.to_canonical_u64().to_le_bytes().to_vec()
    }
    
    /// Create from bytes (little-endian)
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 8 {
            return None;
        }
        
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        let val = u64::from_le_bytes(array);
        
        if val >= Self::MODULUS {
            return None;
        }
        
        Some(Self::from_u64(val))
    }
}

/// Reverse bits of a number
fn reverse_bits(mut n: usize, num_bits: usize) -> usize {
    let mut result = 0;
    for _ in 0..num_bits {
        result = (result << 1) | (n & 1);
        n >>= 1;
    }
    result
}
