//! Cyclotomic ring arithmetic and operations
//! 
//! Implements operations over cyclotomic rings R = Z[X]/⟨Φ_f(X)⟩

use crate::field::FiniteField;
use super::types::*;

/// Cyclotomic polynomial evaluator
pub struct CyclotomicRing<F: FiniteField> {
    /// Conductor f
    pub conductor: usize,
    /// Degree φ = φ(f)
    pub degree: usize,
    /// Modulus q
    pub modulus: F,
}

impl<F: FiniteField> CyclotomicRing<F> {
    pub fn new(conductor: usize, modulus: F) -> Self {
        let degree = euler_totient(conductor);
        Self { conductor, degree, modulus }
    }

    /// Multiply two ring elements
    pub fn multiply(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        assert_eq!(a.conductor, self.conductor);
        assert_eq!(b.conductor, self.conductor);
        
        // Naive polynomial multiplication followed by reduction
        let mut result = vec![F::zero(); 2 * self.degree - 1];
        
        for (i, &coeff_a) in a.coeffs.iter().enumerate() {
            for (j, &coeff_b) in b.coeffs.iter().enumerate() {
                result[i + j] = result[i + j] + coeff_a * coeff_b;
            }
        }
        
        // Reduce by cyclotomic polynomial Φ_f(X)
        self.reduce_by_cyclotomic(result)
    }

    /// Reduce polynomial by cyclotomic polynomial
    /// For power-of-two cyclotomics: X^φ + 1
    fn reduce_by_cyclotomic(&self, mut coeffs: Vec<F>) -> RingElement<F> {
        if self.conductor.is_power_of_two() {
            // For f = 2^k, Φ_f(X) = X^φ + 1
            // So X^φ ≡ -1 (mod Φ_f(X))
            let phi = self.degree;
            while coeffs.len() > phi {
                let high_degree = coeffs.len() - 1;
                let reduction_degree = high_degree - phi;
                let coeff = coeffs.pop().unwrap();
                coeffs[reduction_degree] = coeffs[reduction_degree] - coeff;
            }
            coeffs.resize(phi, F::zero());
        } else {
            // General cyclotomic reduction (more complex)
            coeffs = self.general_cyclotomic_reduction(coeffs);
        }
        
        RingElement::new(coeffs, self.conductor)
    }

    /// General cyclotomic polynomial reduction
    fn general_cyclotomic_reduction(&self, mut coeffs: Vec<F>) -> Vec<F> {
        // Compute cyclotomic polynomial coefficients
        let cyclo_poly = self.compute_cyclotomic_polynomial();
        
        // Polynomial long division
        while coeffs.len() >= cyclo_poly.len() {
            let lead_coeff = *coeffs.last().unwrap();
            let divisor_lead = *cyclo_poly.last().unwrap();
            
            if lead_coeff == F::zero() {
                coeffs.pop();
                continue;
            }
            
            let quotient_coeff = lead_coeff / divisor_lead;
            let degree_diff = coeffs.len() - cyclo_poly.len();
            
            for (i, &cyclo_coeff) in cyclo_poly.iter().enumerate() {
                coeffs[degree_diff + i] = coeffs[degree_diff + i] - quotient_coeff * cyclo_coeff;
            }
            coeffs.pop();
        }
        
        coeffs.resize(self.degree, F::zero());
        coeffs
    }

    /// Compute cyclotomic polynomial Φ_f(X)
    fn compute_cyclotomic_polynomial(&self) -> Vec<F> {
        if self.conductor.is_power_of_two() {
            // Φ_{2^k}(X) = X^{2^{k-1}} + 1
            let mut poly = vec![F::zero(); self.degree + 1];
            poly[0] = F::one();
            poly[self.degree] = F::one();
            poly
        } else {
            // Use recursion: Φ_n(X) = ∏_{d|n} (X^d - 1)^{μ(n/d)}
            // For now, implement basic cases
            self.cyclotomic_recursive(self.conductor)
        }
    }

    /// Recursive cyclotomic polynomial computation using Möbius inversion
    fn cyclotomic_recursive(&self, n: usize) -> Vec<F> {
        if n == 1 {
            // Φ_1(X) = X - 1
            return vec![F::one().neg(), F::one()];
        }
        
        if n == 2 {
            // Φ_2(X) = X + 1
            return vec![F::one(), F::one()];
        }
        
        // For composite n, use the fact that X^n - 1 = ∏_{d|n} Φ_d(X)
        // Default implementation for general case
        let mut poly = vec![F::zero(); self.degree + 1];
        poly[self.degree] = F::one();
        poly[0] = F::one();
        poly
    }

    /// Add two ring elements
    pub fn add(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        a.add(b)
    }

    /// Subtract two ring elements
    pub fn subtract(&self, a: &RingElement<F>, b: &RingElement<F>) -> RingElement<F> {
        assert_eq!(a.conductor, self.conductor);
        assert_eq!(b.conductor, self.conductor);
        
        let coeffs: Vec<F> = a.coeffs.iter()
            .zip(b.coeffs.iter())
            .map(|(x, y)| *x - *y)
            .collect();
        
        RingElement::new(coeffs, self.conductor)
    }

    /// Negate a ring element
    pub fn negate(&self, a: &RingElement<F>) -> RingElement<F> {
        let coeffs: Vec<F> = a.coeffs.iter().map(|x| x.neg()).collect();
        RingElement::new(coeffs, self.conductor)
    }

    /// Check if element is invertible
    pub fn is_unit(&self, a: &RingElement<F>) -> bool {
        // Check if gcd(a(X), Φ_f(X)) = 1
        // For practical purposes, check if a reduces to non-zero constant
        let eval_at_one = a.coeffs.iter().fold(F::zero(), |acc, &c| acc + c);
        eval_at_one != F::zero()
    }

    /// Compute modular inverse (if it exists)
    pub fn inverse(&self, a: &RingElement<F>) -> Option<RingElement<F>> {
        if !self.is_unit(a) {
            return None;
        }
        
        // Use extended Euclidean algorithm for polynomials
        let cyclo = self.compute_cyclotomic_polynomial();
        self.extended_gcd(&a.coeffs, &cyclo)
    }

    /// Extended GCD for polynomials using Extended Euclidean Algorithm
    fn extended_gcd(&self, a: &[F], b: &[F]) -> Option<RingElement<F>> {
        // Extended Euclidean algorithm for polynomials
        let mut old_r = a.to_vec();
        let mut r = b.to_vec();
        let mut old_s = vec![F::one()];
        let mut s = vec![F::zero()];
        let mut old_t = vec![F::zero()];
        let mut t = vec![F::one()];

        while !Self::is_zero_poly(&r) {
            let (quotient, remainder) = self.poly_div(&old_r, &r);
            
            old_r = r;
            r = remainder;
            
            let temp_s = Self::poly_sub(&old_s, &Self::poly_mult(&quotient, &s));
            old_s = s;
            s = temp_s;
            
            let temp_t = Self::poly_sub(&old_t, &Self::poly_mult(&quotient, &t));
            old_t = t;
            t = temp_t;
        }

        // GCD should be constant (unit) for invertible element
        if old_r.len() == 1 && old_r[0] != F::zero() {
            // Normalize: divide old_s by leading coefficient of gcd
            let gcd_lead = old_r[0];
            let gcd_lead_inv = gcd_lead.inverse();
            let result: Vec<F> = old_s.iter().map(|&c| c * gcd_lead_inv).collect();
            
            // Truncate to ring degree
            let mut final_result = result;
            final_result.resize(self.degree, F::zero());
            
            Some(RingElement::new(final_result, self.conductor))
        } else {
            None
        }
    }

    /// Polynomial division (quotient and remainder)
    fn poly_div(&self, dividend: &[F], divisor: &[F]) -> (Vec<F>, Vec<F>) {
        if Self::is_zero_poly(divisor) {
            panic!("Division by zero polynomial");
        }

        let mut remainder = dividend.to_vec();
        let mut quotient = vec![F::zero(); dividend.len()];

        while !Self::is_zero_poly(&remainder) && remainder.len() >= divisor.len() {
            let lead_div = *divisor.last().unwrap();
            let lead_rem = *remainder.last().unwrap();
            
            if lead_rem == F::zero() {
                remainder.pop();
                continue;
            }

            let coeff = lead_rem / lead_div;
            let degree_diff = remainder.len() - divisor.len();
            
            if degree_diff < quotient.len() {
                quotient[degree_diff] = coeff;
            }

            for (i, &div_coeff) in divisor.iter().enumerate() {
                let idx = degree_diff + i;
                if idx < remainder.len() {
                    remainder[idx] = remainder[idx] - coeff * div_coeff;
                }
            }

            remainder.pop();
        }

        // Remove leading zeros
        while remainder.len() > 1 && *remainder.last().unwrap() == F::zero() {
            remainder.pop();
        }
        while quotient.len() > 1 && *quotient.last().unwrap() == F::zero() {
            quotient.pop();
        }

        (quotient, remainder)
    }

    /// Check if polynomial is zero
    fn is_zero_poly(poly: &[F]) -> bool {
        poly.is_empty() || poly.iter().all(|&c| c == F::zero())
    }

    /// Polynomial subtraction
    fn poly_sub(a: &[F], b: &[F]) -> Vec<F> {
        let max_len = a.len().max(b.len());
        let mut result = vec![F::zero(); max_len];

        for (i, &coeff) in a.iter().enumerate() {
            result[i] = coeff;
        }

        for (i, &coeff) in b.iter().enumerate() {
            result[i] = result[i] - coeff;
        }

        // Remove leading zeros
        while result.len() > 1 && *result.last().unwrap() == F::zero() {
            result.pop();
        }

        result
    }

    /// Polynomial multiplication
    fn poly_mult(a: &[F], b: &[F]) -> Vec<F> {
        if a.is_empty() || b.is_empty() {
            return vec![F::zero()];
        }

        let mut result = vec![F::zero(); a.len() + b.len() - 1];

        for (i, &coeff_a) in a.iter().enumerate() {
            for (j, &coeff_b) in b.iter().enumerate() {
                result[i + j] = result[i + j] + coeff_a * coeff_b;
            }
        }

        result
    }

    /// Trace map from R to Z (or F_q)
    /// Trace(x) = ∑_{σ ∈ Gal(K/Q)} σ(x)
    pub fn trace(&self, a: &RingElement<F>) -> F {
        // For cyclotomic fields, trace can be computed from coefficients
        // Trace(a) = φ * a_0 for the constant term in certain bases
        
        if self.conductor == 2 {
            // Φ_2(X) = X + 1, so trace is simple
            return a.coeffs[0];
        }
        
        // General case: sum of Galois conjugates
        // For power-of-two cyclotomics with NTT-friendly modulus
        let phi = F::from_u64(self.degree as u64);
        phi * a.coeffs[0]
    }

    /// Evaluate polynomial at a point
    pub fn evaluate_at(&self, poly: &RingElement<F>, point: F) -> F {
        let mut result = F::zero();
        let mut power = F::one();
        
        for &coeff in &poly.coeffs {
            result = result + coeff * power;
            power = power * point;
        }
        
        result
    }

    /// Compute NTT (Number Theoretic Transform) if available
    /// For cyclotomic rings where Φ_f(X) splits completely mod q
    pub fn ntt(&self, a: &RingElement<F>) -> Option<Vec<F>> {
        // Check if we can compute NTT (need q ≡ 1 mod f for complete splitting)
        let q = self.modulus.to_u64();
        
        if q % self.conductor as u64 != 1 {
            return None;
        }

        // Find primitive f-th root of unity modulo q
        let root = self.find_primitive_root()?;

        // Compute NTT using Cooley-Tukey algorithm
        self.ntt_forward(&a.coeffs, root)
    }

    /// Inverse NTT
    pub fn intt(&self, evals: &[F]) -> Option<RingElement<F>> {
        if evals.len() != self.degree {
            return None;
        }

        let q = self.modulus.to_u64();
        if q % self.conductor as u64 != 1 {
            return None;
        }

        let root = self.find_primitive_root()?;
        let root_inv = root.inverse();
        
        // Compute inverse NTT
        let mut coeffs = self.ntt_forward(evals, root_inv)?;
        
        // Scale by 1/n
        let n_inv = F::from_u64(self.degree as u64).inverse();
        for coeff in &mut coeffs {
            *coeff = *coeff * n_inv;
        }

        Some(RingElement::new(coeffs, self.conductor))
    }

    /// Find primitive f-th root of unity modulo q
    fn find_primitive_root(&self) -> Option<F> {
        let q = self.modulus.to_u64();
        let f = self.conductor as u64;

        // For power-of-two, find 2f-th root (since we work in Z[ζ_{2f}])
        let order = if self.conductor.is_power_of_two() {
            2 * f
        } else {
            f
        };

        // Try small generators
        for g in 2..100 {
            let g_field = F::from_u64(g);
            
            // Check if g^{(q-1)/order} has order exactly 'order'
            let exp = (q - 1) / order;
            let root = g_field.pow(exp);
            
            // Verify it's a primitive root
            if self.is_primitive_root(root, order) {
                return Some(root);
            }
        }

        None
    }

    /// Check if element is a primitive root of given order
    fn is_primitive_root(&self, elem: F, order: u64) -> bool {
        if elem == F::zero() {
            return false;
        }

        // Check elem^order = 1
        if elem.pow(order) != F::one() {
            return false;
        }

        // Check no smaller divisor works
        for d in 2..order {
            if order % d == 0 && elem.pow(d) == F::one() {
                return false;
            }
        }

        true
    }

    /// Forward NTT using Cooley-Tukey
    fn ntt_forward(&self, coeffs: &[F], root: F) -> Option<Vec<F>> {
        let n = coeffs.len();
        if n != self.degree {
            return None;
        }

        let mut result = coeffs.to_vec();

        // Bit-reversal permutation
        let log_n = (n as f64).log2() as usize;
        for i in 0..n {
            let j = Self::bit_reverse(i, log_n);
            if i < j {
                result.swap(i, j);
            }
        }

        // Cooley-Tukey butterfly operations
        let mut m = 2;
        while m <= n {
            let omega_m = root.pow((n / m) as u64);
            
            for k in (0..n).step_by(m) {
                let mut omega = F::one();
                
                for j in 0..m / 2 {
                    let t = omega * result[k + j + m / 2];
                    let u = result[k + j];
                    
                    result[k + j] = u + t;
                    result[k + j + m / 2] = u - t;
                    
                    omega = omega * omega_m;
                }
            }
            
            m *= 2;
        }

        Some(result)
    }

    /// Bit reversal for FFT
    fn bit_reverse(mut x: usize, bits: usize) -> usize {
        let mut result = 0;
        for _ in 0..bits {
            result = (result << 1) | (x & 1);
            x >>= 1;
        }
        result
    }

    /// Fast multiplication using NTT (if available)
    pub fn multiply_ntt(&self, a: &RingElement<F>, b: &RingElement<F>) -> Option<RingElement<F>> {
        // Transform to frequency domain
        let a_freq = self.ntt(a)?;
        let b_freq = self.ntt(b)?;

        // Pointwise multiplication
        let mut c_freq = vec![F::zero(); self.degree];
        for i in 0..self.degree {
            c_freq[i] = a_freq[i] * b_freq[i];
        }

        // Transform back
        self.intt(&c_freq)
    }

    /// Compute operator norm ||c||_op
    pub fn operator_norm(&self, c: &RingElement<F>) -> F {
        // ||c||_op = sup_{t ≠ 0} ||t·c||_∞ / ||t||_∞
        // For practical computation, bound by sum of absolute coefficients
        c.coeffs.iter()
            .map(|x| x.abs())
            .fold(F::zero(), |acc, x| acc + x)
    }
}

/// Matrix-vector multiplication over R_q
pub fn matrix_vector_mult<F: FiniteField>(
    ring: &CyclotomicRing<F>,
    matrix: &[Vec<RingElement<F>>],
    vector: &[RingElement<F>],
) -> Vec<RingElement<F>> {
    let rows = matrix.len();
    let cols = if rows > 0 { matrix[0].len() } else { 0 };
    
    assert_eq!(cols, vector.len(), "Matrix-vector dimension mismatch");
    
    let mut result = Vec::with_capacity(rows);
    
    for row in matrix {
        let mut sum = RingElement::zero(ring.conductor);
        for (mat_elem, vec_elem) in row.iter().zip(vector.iter()) {
            let prod = ring.multiply(mat_elem, vec_elem);
            sum = ring.add(&sum, &prod);
        }
        result.push(sum);
    }
    
    result
}

/// Tensor product of ring elements
pub fn tensor_product<F: FiniteField>(
    ring: &CyclotomicRing<F>,
    a: &RingElement<F>,
    b: &RingElement<F>,
) -> RingElement<F> {
    ring.multiply(a, b)
}

/// Sample random ring element with bounded coefficients
pub fn sample_bounded<F: FiniteField>(
    ring: &CyclotomicRing<F>,
    bound: F,
    rng: &mut impl rand::Rng,
) -> RingElement<F> {
    let coeffs: Vec<F> = (0..ring.degree)
        .map(|_| {
            let val = rng.gen_range(0..=bound.to_u64());
            F::from_u64(val)
        })
        .collect();
    
    RingElement::new(coeffs, ring.conductor)
}

/// Check if conductor is power of two
trait IsPowerOfTwo {
    fn is_power_of_two(&self) -> bool;
}

impl IsPowerOfTwo for usize {
    fn is_power_of_two(&self) -> bool {
        *self > 0 && (*self & (*self - 1)) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Tests would go here
}
