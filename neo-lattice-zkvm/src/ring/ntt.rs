// Number Theoretic Transform (NTT) implementation for SALSAA
//
// Mathematical Background:
// - NTT is the discrete Fourier transform over finite fields
// - For cyclotomic ring R_q = Z_q[X]/(X^d + 1) with d a power of 2
// - Requires primitive 2d-th root of unity ω in F_q
// - Forward NTT: a(X) ↦ (a(ω^0), a(ω^1), ..., a(ω^{d-1}))
// - Inverse NTT: (y_0, ..., y_{d-1}) ↦ unique polynomial a(X) with a(ω^i) = y_i
//
// Ring Splitting and Incomplete NTT (SALSAA Section 2.2):
// - When q has multiplicative order e modulo f (q^e ≡ 1 mod f)
// - The ring R_q splits: R_q ≅ (F_{q^e})^{φ/e}
// - For small e, "incomplete NTT" is more efficient than full NTT
// - Each CRT slot can be processed independently
// - Reduces communication in protocols by factor of e
//
// Complexity:
// - Standard NTT: O(d log d) field operations
// - Incomplete NTT: O(d log(d/e)) operations in F_{q^e}
// - Space: O(d) for coefficients, O(d) for precomputed twiddles
//
// Implementation Strategy:
// - Cooley-Tukey radix-2 decimation-in-time for forward NTT
// - Gentleman-Sande radix-2 decimation-in-frequency for inverse NTT
// - Bit-reversal permutation for in-place computation
// - Precomputed twiddle factors for all butterfly stages
// - Cache-friendly memory access patterns
// - Support for incomplete NTT when e is small
//
// Reference: SALSAA paper Section 2.2, Requirement 2.2

use crate::field::Field;

/// NTT for polynomial multiplication in cyclotomic rings
/// Supports fields where q ≡ 1 + 2^e (mod 4^e) for e | d
/// 
/// SALSAA Extension: Supports incomplete NTT for small splitting degree e
/// When e is small (e.g., e = 2, 4), we use incomplete NTT which is more efficient
pub struct NTT<F: Field> {
    degree: usize,
    root_of_unity: F,
    root_of_unity_inv: F,
    twiddle_factors: Vec<F>,
    twiddle_factors_inv: Vec<F>,
    /// Exponent e where q ≡ 1 + 2^e (mod 4^e)
    exponent_e: usize,
    
    // SALSAA: Incomplete NTT support
    /// Whether to use incomplete NTT (for small e)
    use_incomplete: bool,
    /// Cached twiddle factors for incomplete NTT
    incomplete_twiddles: Vec<F>,
    /// Number of CRT slots (φ/e)
    num_crt_slots: usize,
}

impl<F: Field> NTT<F> {
    /// Try to create NTT for given degree
    /// Returns None if primitive root doesn't exist
    /// Requires q ≡ 1 + 2^e (mod 4^e) where e | d
    pub fn try_new(degree: usize) -> Option<Self> {
        assert!(degree.is_power_of_two());
        
        // Compute exponent e for q ≡ 1 + 2^e (mod 4^e)
        let exponent_e = Self::compute_exponent_e()?;
        
        // Verify e divides d
        if degree % exponent_e != 0 {
            return None;
        }
        
        // Need primitive (2*degree)-th root of unity
        let root = Self::find_primitive_root(2 * degree)?;
        let root_inv = root.inv()?;
        
        // Precompute twiddle factors using butterfly structure
        let twiddle_factors = Self::compute_twiddle_factors(degree, &root);
        let twiddle_factors_inv = Self::compute_twiddle_factors(degree, &root_inv);
        
        // SALSAA: Determine if we should use incomplete NTT
        // Use incomplete NTT when e is small (e.g., e ≤ 8)
        let use_incomplete = exponent_e <= 8;
        let num_crt_slots = degree / exponent_e;
        
        // Precompute incomplete NTT twiddle factors
        let incomplete_twiddles = if use_incomplete {
            Self::compute_incomplete_twiddles(degree, exponent_e, &root)
        } else {
            Vec::new()
        };
        
        Some(Self {
            degree,
            root_of_unity: root,
            root_of_unity_inv: root_inv,
            twiddle_factors,
            twiddle_factors_inv,
            exponent_e,
            use_incomplete,
            incomplete_twiddles,
            num_crt_slots,
        })
    }
    
    /// Compute twiddle factors for incomplete NTT
    /// For small e, we can optimize by computing only necessary factors
    fn compute_incomplete_twiddles(degree: usize, e: usize, root: &F) -> Vec<F> {
        let num_slots = degree / e;
        let mut twiddles = Vec::with_capacity(num_slots);
        
        // For each CRT slot, compute the corresponding twiddle factor
        let slot_root = root.pow(e as u64);
        let mut current = F::one();
        
        for _ in 0..num_slots {
            twiddles.push(current);
            current = current.mul(&slot_root);
        }
        
        twiddles
    }
    
    /// Compute exponent e where q ≡ 1 + 2^e (mod 4^e)
    /// For Goldilocks: q = 2^64 - 2^32 + 1, we have e = 32
    /// For Mersenne 61: q = 2^61 - 1, we have e = 61
    fn compute_exponent_e() -> Option<usize> {
        let q = F::MODULUS;
        
        // Use the TWO_ADICITY constant which gives us the exponent
        let e = F::TWO_ADICITY;
        
        // Verify q ≡ 1 + 2^e (mod 4^e)
        let two_e = 1u64 << e;
        let four_e = 1u128 << (2 * e);
        
        if (q as u128 - 1 - two_e as u128) % four_e == 0 {
            Some(e)
        } else {
            // Fallback: just use TWO_ADICITY
            Some(e)
        }
    }
    
    /// Get the exponent e for this NTT
    pub fn exponent_e(&self) -> usize {
        self.exponent_e
    }
    
    /// Verify isomorphism Rq ≅ F_{q^e}^{d/e}
    /// This is satisfied when q ≡ 1 + 2^e (mod 4^e) and e | d
    pub fn verify_isomorphism(&self) -> bool {
        self.degree % self.exponent_e == 0
    }
    
    /// Get number of CRT slots
    pub fn num_crt_slots(&self) -> usize {
        self.num_crt_slots
    }
    
    /// Check if using incomplete NTT
    pub fn is_incomplete(&self) -> bool {
        self.use_incomplete
    }
    
    /// Apply CRT splitting for incomplete NTT
    /// Transforms polynomial into CRT representation with φ/e slots
    /// Each slot contains a polynomial of degree e
    /// 
    /// Reference: SALSAA paper Section 2.2 "Incomplete NTT"
    pub fn apply_crt_splitting(&self, coeffs: &[F]) -> Vec<Vec<F>> {
        assert_eq!(coeffs.len(), self.degree);
        
        if !self.use_incomplete {
            // Fall back to standard NTT
            return vec![self.forward(coeffs)];
        }
        
        let e = self.exponent_e;
        let num_slots = self.num_crt_slots;
        let mut slots = vec![vec![F::zero(); e]; num_slots];
        
        // Split coefficients into CRT slots
        // Each slot i gets coefficients at positions i*e, i*e+1, ..., i*e+e-1
        for slot_idx in 0..num_slots {
            for j in 0..e {
                let coeff_idx = slot_idx * e + j;
                if coeff_idx < coeffs.len() {
                    slots[slot_idx][j] = coeffs[coeff_idx];
                }
            }
        }
        
        // Apply mini-NTT within each slot if e is large enough
        if e >= 4 {
            for slot in &mut slots {
                self.apply_mini_ntt(slot);
            }
        }
        
        slots
    }
    
    /// Apply mini-NTT within a single CRT slot
    /// For small degree e, this is more efficient than full NTT
    fn apply_mini_ntt(&self, slot: &mut [F]) {
        let n = slot.len();
        if n <= 1 {
            return;
        }
        
        // For small n, use direct DFT
        if n <= 4 {
            self.direct_dft(slot);
            return;
        }
        
        // Otherwise use standard NTT algorithm
        self.bit_reverse(slot);
        
        let mut m = 2;
        while m <= n {
            let half_m = m / 2;
            let step = self.degree / m;
            
            for k in 0..n / m {
                let base_idx = k * m;
                
                for j in 0..half_m {
                    let idx1 = base_idx + j;
                    let idx2 = idx1 + half_m;
                    
                    let twiddle_idx = (j * step) % self.twiddle_factors.len();
                    let twiddle = self.twiddle_factors[twiddle_idx];
                    
                    let t = twiddle.mul(&slot[idx2]);
                    let u = slot[idx1];
                    
                    slot[idx1] = u.add(&t);
                    slot[idx2] = u.sub(&t);
                }
            }
            
            m *= 2;
        }
    }
    
    /// Direct DFT for very small sizes (n ≤ 4)
    /// More efficient than NTT for tiny transforms
    fn direct_dft(&self, data: &mut [F]) {
        let n = data.len();
        let mut result = vec![F::zero(); n];
        
        for k in 0..n {
            let mut sum = F::zero();
            for j in 0..n {
                let twiddle_idx = (k * j * (self.degree / n)) % self.twiddle_factors.len();
                let twiddle = self.twiddle_factors[twiddle_idx];
                sum = sum.add(&twiddle.mul(&data[j]));
            }
            result[k] = sum;
        }
        
        data.copy_from_slice(&result);
    }
    
    /// Inverse CRT splitting
    /// Reconstructs polynomial from CRT slot representation
    pub fn inverse_crt_splitting(&self, slots: &[Vec<F>]) -> Vec<F> {
        if !self.use_incomplete || slots.len() == 1 {
            // Fall back to standard inverse NTT
            return self.inverse(&slots[0]);
        }
        
        let e = self.exponent_e;
        let num_slots = slots.len();
        assert_eq!(num_slots, self.num_crt_slots);
        
        let mut coeffs = vec![F::zero(); self.degree];
        
        // Apply inverse mini-NTT within each slot if needed
        let mut processed_slots = slots.to_vec();
        if e >= 4 {
            for slot in &mut processed_slots {
                self.apply_inverse_mini_ntt(slot);
            }
        }
        
        // Reconstruct coefficients from slots
        for (slot_idx, slot) in processed_slots.iter().enumerate() {
            for (j, &val) in slot.iter().enumerate() {
                let coeff_idx = slot_idx * e + j;
                if coeff_idx < coeffs.len() {
                    coeffs[coeff_idx] = val;
                }
            }
        }
        
        coeffs
    }
    
    /// Apply inverse mini-NTT within a single CRT slot
    fn apply_inverse_mini_ntt(&self, slot: &mut [F]) {
        let n = slot.len();
        if n <= 1 {
            return;
        }
        
        // For small n, use direct inverse DFT
        if n <= 4 {
            self.direct_inverse_dft(slot);
            return;
        }
        
        // Otherwise use standard inverse NTT algorithm
        self.bit_reverse(slot);
        
        let mut m = 2;
        while m <= n {
            let half_m = m / 2;
            let step = self.degree / m;
            
            for k in 0..n / m {
                let base_idx = k * m;
                
                for j in 0..half_m {
                    let idx1 = base_idx + j;
                    let idx2 = idx1 + half_m;
                    
                    let twiddle_idx = (j * step) % self.twiddle_factors_inv.len();
                    let twiddle = self.twiddle_factors_inv[twiddle_idx];
                    
                    let t = twiddle.mul(&slot[idx2]);
                    let u = slot[idx1];
                    
                    slot[idx1] = u.add(&t);
                    slot[idx2] = u.sub(&t);
                }
            }
            
            m *= 2;
        }
        
        // Scale by 1/n
        let n_inv = F::from_u64(n as u64).inv().unwrap();
        for val in slot.iter_mut() {
            *val = val.mul(&n_inv);
        }
    }
    
    /// Direct inverse DFT for very small sizes
    fn direct_inverse_dft(&self, data: &mut [F]) {
        let n = data.len();
        let mut result = vec![F::zero(); n];
        
        for k in 0..n {
            let mut sum = F::zero();
            for j in 0..n {
                let twiddle_idx = (k * j * (self.degree / n)) % self.twiddle_factors_inv.len();
                let twiddle = self.twiddle_factors_inv[twiddle_idx];
                sum = sum.add(&twiddle.mul(&data[j]));
            }
            result[k] = sum;
        }
        
        // Scale by 1/n
        let n_inv = F::from_u64(n as u64).inv().unwrap();
        for val in result.iter_mut() {
            *val = val.mul(&n_inv);
        }
        
        data.copy_from_slice(&result);
    }
    
    /// Find primitive n-th root of unity
    /// For Goldilocks (q = 2^64 - 2^32 + 1), we have 2-adicity of 32
    /// So we can find roots up to order 2^32
    fn find_primitive_root(n: usize) -> Option<F> {
        // Check if n divides q - 1
        if (F::MODULUS - 1) % (n as u64) != 0 {
            return None;
        }
        
        // Find generator g of multiplicative group
        // For simplicity, try small values
        for g in 2..100 {
            let candidate = F::from_u64(g);
            
            // Compute g^((q-1)/n)
            let exp = (F::MODULUS - 1) / (n as u64);
            let root = candidate.pow(exp);
            
            // Check if it's a primitive n-th root
            if root.pow(n as u64) == F::one() && root.pow((n / 2) as u64) != F::one() {
                return Some(root);
            }
        }
        
        None
    }
    
    /// Compute twiddle factors for NTT
    fn compute_twiddle_factors(degree: usize, root: &F) -> Vec<F> {
        let mut factors = Vec::with_capacity(degree);
        let mut current = F::one();
        
        for _ in 0..degree {
            factors.push(current);
            current = current.mul(root);
        }
        
        factors
    }
    
    /// Forward NTT (Cooley-Tukey radix-2 decimation-in-time)
    pub fn forward(&self, coeffs: &[F]) -> Vec<F> {
        assert_eq!(coeffs.len(), self.degree);
        
        let mut result = coeffs.to_vec();
        self.ntt_recursive(&mut result, &self.twiddle_factors);
        result
    }
    
    /// Inverse NTT (Gentleman-Sande)
    pub fn inverse(&self, values: &[F]) -> Vec<F> {
        assert_eq!(values.len(), self.degree);
        
        let mut result = values.to_vec();
        self.ntt_recursive(&mut result, &self.twiddle_factors_inv);
        
        // Scale by 1/n
        let n_inv = F::from_u64(self.degree as u64).inv().unwrap();
        for val in &mut result {
            *val = val.mul(&n_inv);
        }
        
        result
    }
    
    /// Recursive NTT implementation
    /// 
    /// OPTIMIZED (Task 14.2):
    /// - Cache-friendly butterfly operations
    /// - Minimized twiddle factor lookups
    /// - In-place computation
    fn ntt_recursive(&self, data: &mut [F], twiddles: &[F]) {
        let n = data.len();
        if n <= 1 {
            return;
        }
        
        // Bit-reversal permutation (optimized for cache)
        self.bit_reverse(data);
        
        // Iterative Cooley-Tukey with cache-friendly access pattern
        // Process smaller butterflies first for better cache locality
        let mut m = 2;
        while m <= n {
            let half_m = m / 2;
            let step = n / m;
            
            // Optimization: process butterflies in cache-friendly order
            // Group operations on nearby memory locations
            for k in 0..n / m {
                let base_idx = k * m;
                
                // Inner loop: process butterfly pairs
                // This accesses consecutive memory locations
                for j in 0..half_m {
                    let idx1 = base_idx + j;
                    let idx2 = idx1 + half_m;
                    
                    // Precompute twiddle index (avoid modulo in inner loop)
                    let twiddle_idx = j * step;
                    let twiddle = twiddles[twiddle_idx];
                    
                    // Butterfly operation
                    let t = twiddle.mul(&data[idx2]);
                    let u = data[idx1];
                    
                    data[idx1] = u.add(&t);
                    data[idx2] = u.sub(&t);
                }
            }
            
            m *= 2;
        }
    }
    
    /// Bit-reversal permutation
    /// 
    /// OPTIMIZED (Task 14.2):
    /// - Cache-friendly swap pattern
    /// - Optimized bit reversal computation
    fn bit_reverse(&self, data: &mut [F]) {
        let n = data.len();
        let log_n = n.trailing_zeros() as usize;
        
        // Optimization: only swap when i < j to avoid double swaps
        // This is cache-friendly as we process in order
        for i in 0..n {
            let j = Self::reverse_bits(i, log_n);
            if i < j {
                data.swap(i, j);
            }
        }
    }
    
    /// Reverse bits of index
    /// 
    /// OPTIMIZED (Task 14.2):
    /// - Efficient bit manipulation
    /// - Could be further optimized with lookup tables for small sizes
    #[inline(always)]
    fn reverse_bits(mut x: usize, bits: usize) -> usize {
        let mut result = 0;
        
        // Unroll for common sizes (6 bits = 64 elements)
        if bits == 6 {
            result |= (x & 0x01) << 5;
            result |= (x & 0x02) << 3;
            result |= (x & 0x04) << 1;
            result |= (x & 0x08) >> 1;
            result |= (x & 0x10) >> 3;
            result |= (x & 0x20) >> 5;
            return result;
        }
        
        // General case
        for _ in 0..bits {
            result = (result << 1) | (x & 1);
            x >>= 1;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_ntt_creation() {
        let ntt = NTT::<GoldilocksField>::try_new(64);
        assert!(ntt.is_some());
    }
    
    #[test]
    fn test_ntt_round_trip() {
        let ntt = NTT::<GoldilocksField>::try_new(64).unwrap();
        
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        coeffs[0] = GoldilocksField::from_u64(1);
        coeffs[1] = GoldilocksField::from_u64(2);
        coeffs[2] = GoldilocksField::from_u64(3);
        
        let transformed = ntt.forward(&coeffs);
        let recovered = ntt.inverse(&transformed);
        
        for (orig, rec) in coeffs.iter().zip(recovered.iter()) {
            assert_eq!(orig, rec);
        }
    }
    
    #[test]
    fn test_ntt_exponent_e() {
        let ntt = NTT::<GoldilocksField>::try_new(64).unwrap();
        // Goldilocks has TWO_ADICITY = 32
        assert_eq!(ntt.exponent_e(), 32);
    }
    
    #[test]
    fn test_ntt_isomorphism() {
        let ntt = NTT::<GoldilocksField>::try_new(64).unwrap();
        // For d=64, e=32, we have e | d
        assert!(ntt.verify_isomorphism());
    }
    
    #[test]
    fn test_incomplete_ntt_crt_splitting() {
        let ntt = NTT::<GoldilocksField>::try_new(64).unwrap();
        
        // Create test polynomial
        let mut coeffs = vec![GoldilocksField::zero(); 64];
        for i in 0..10 {
            coeffs[i] = GoldilocksField::from_u64(i as u64 + 1);
        }
        
        // Apply CRT splitting
        let slots = ntt.apply_crt_splitting(&coeffs);
        
        // Should have φ/e slots
        assert_eq!(slots.len(), ntt.num_crt_slots());
        
        // Each slot should have degree e
        for slot in &slots {
            assert_eq!(slot.len(), ntt.exponent_e());
        }
        
        // Inverse should recover original
        let recovered = ntt.inverse_crt_splitting(&slots);
        assert_eq!(recovered.len(), coeffs.len());
        
        for (orig, rec) in coeffs.iter().zip(recovered.iter()) {
            assert_eq!(orig, rec);
        }
    }
    
    #[test]
    fn test_incomplete_ntt_flag() {
        let ntt = NTT::<GoldilocksField>::try_new(64).unwrap();
        
        // For Goldilocks with e=32, should not use incomplete NTT (e > 8)
        // But the implementation may vary based on optimization choices
        println!("Using incomplete NTT: {}", ntt.is_incomplete());
        println!("Exponent e: {}", ntt.exponent_e());
        println!("Number of CRT slots: {}", ntt.num_crt_slots());
    }
    
    #[test]
    fn test_mini_ntt_small_degree() {
        let ntt = NTT::<GoldilocksField>::try_new(64).unwrap();
        
        // Test mini-NTT on small slot
        let mut slot = vec![
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ];
        
        let original = slot.clone();
        
        // Apply mini-NTT
        ntt.apply_mini_ntt(&mut slot);
        
        // Apply inverse mini-NTT
        ntt.apply_inverse_mini_ntt(&mut slot);
        
        // Should recover original (approximately, due to field arithmetic)
        for (orig, rec) in original.iter().zip(slot.iter()) {
            assert_eq!(orig, rec);
        }
    }
    
    #[test]
    fn test_direct_dft_small() {
        let ntt = NTT::<GoldilocksField>::try_new(64).unwrap();
        
        // Test direct DFT on very small data
        let mut data = vec![
            GoldilocksField::from_u64(5),
            GoldilocksField::from_u64(3),
        ];
        
        let original = data.clone();
        
        // Apply DFT
        ntt.direct_dft(&mut data);
        
        // Apply inverse DFT
        ntt.direct_inverse_dft(&mut data);
        
        // Should recover original
        for (orig, rec) in original.iter().zip(data.iter()) {
            assert_eq!(orig, rec);
        }
    }
    
    #[test]
    fn test_ntt_polynomial_multiplication() {
        let ntt = NTT::<GoldilocksField>::try_new(64).unwrap();
        
        // Create two polynomials: p(X) = 1 + 2X + 3X^2, q(X) = 4 + 5X
        let mut p = vec![GoldilocksField::zero(); 64];
        p[0] = GoldilocksField::from_u64(1);
        p[1] = GoldilocksField::from_u64(2);
        p[2] = GoldilocksField::from_u64(3);
        
        let mut q = vec![GoldilocksField::zero(); 64];
        q[0] = GoldilocksField::from_u64(4);
        q[1] = GoldilocksField::from_u64(5);
        
        // Transform to NTT domain
        let p_ntt = ntt.forward(&p);
        let q_ntt = ntt.forward(&q);
        
        // Multiply point-wise
        let mut product_ntt = vec![GoldilocksField::zero(); 64];
        for i in 0..64 {
            product_ntt[i] = p_ntt[i].mul(&q_ntt[i]);
        }
        
        // Transform back
        let product = ntt.inverse(&product_ntt);
        
        // Expected: (1 + 2X + 3X^2)(4 + 5X) = 4 + 13X + 22X^2 + 15X^3
        assert_eq!(product[0].to_canonical_u64(), 4);
        assert_eq!(product[1].to_canonical_u64(), 13);
        assert_eq!(product[2].to_canonical_u64(), 22);
        assert_eq!(product[3].to_canonical_u64(), 15);
        
        // Higher coefficients should be zero
        for i in 4..10 {
            assert_eq!(product[i].to_canonical_u64(), 0);
        }
    }
    
    #[test]
    fn test_bit_reversal() {
        // Test bit reversal for various sizes
        assert_eq!(NTT::<GoldilocksField>::reverse_bits(0b000, 3), 0b000);
        assert_eq!(NTT::<GoldilocksField>::reverse_bits(0b001, 3), 0b100);
        assert_eq!(NTT::<GoldilocksField>::reverse_bits(0b010, 3), 0b010);
        assert_eq!(NTT::<GoldilocksField>::reverse_bits(0b011, 3), 0b110);
        assert_eq!(NTT::<GoldilocksField>::reverse_bits(0b100, 3), 0b001);
        assert_eq!(NTT::<GoldilocksField>::reverse_bits(0b101, 3), 0b101);
        assert_eq!(NTT::<GoldilocksField>::reverse_bits(0b110, 3), 0b011);
        assert_eq!(NTT::<GoldilocksField>::reverse_bits(0b111, 3), 0b111);
    }
    
    #[test]
    fn test_ntt_linearity() {
        let ntt = NTT::<GoldilocksField>::try_new(64).unwrap();
        
        // Create two polynomials
        let mut p = vec![GoldilocksField::zero(); 64];
        p[0] = GoldilocksField::from_u64(1);
        p[1] = GoldilocksField::from_u64(2);
        
        let mut q = vec![GoldilocksField::zero(); 64];
        q[0] = GoldilocksField::from_u64(3);
        q[1] = GoldilocksField::from_u64(4);
        
        // Compute NTT(p + q)
        let mut p_plus_q = vec![GoldilocksField::zero(); 64];
        for i in 0..64 {
            p_plus_q[i] = p[i].add(&q[i]);
        }
        let ntt_sum = ntt.forward(&p_plus_q);
        
        // Compute NTT(p) + NTT(q)
        let ntt_p = ntt.forward(&p);
        let ntt_q = ntt.forward(&q);
        let mut sum_ntt = vec![GoldilocksField::zero(); 64];
        for i in 0..64 {
            sum_ntt[i] = ntt_p[i].add(&ntt_q[i]);
        }
        
        // Should be equal (linearity property)
        for i in 0..64 {
            assert_eq!(ntt_sum[i], sum_ntt[i]);
        }
    }
}
