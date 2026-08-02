//! Strong Sampling Sets (Appendix B from the paper)
//! 
//! Implements exact and approximate strong sampling sets for cyclotomic rings

use crate::field::FiniteField;
use super::types::*;
use super::cyclotomic::*;

/// Exact Strong Sampling Set based on Lyubashevsky-Seiler (Theorem 6, Corollary 1)
pub struct ExactStrongSampling<F: FiniteField> {
    ring: CyclotomicRing<F>,
    /// Bound β on coefficients
    beta: usize,
}

impl<F: FiniteField> ExactStrongSampling<F> {
    pub fn new(ring: CyclotomicRing<F>, beta: usize) -> Self {
        Self { ring, beta }
    }

    /// Generate exact strong sampling set
    /// For power-of-two cyclotomics with φ ≥ k > 1, q = 2k + 1 (mod 4k)
    /// Elements with ||c||_∞ ≤ β < 1/√k · q^{1/k}
    pub fn generate(&self) -> Result<StrongSamplingSet<F>, String> {
        // Check if we can use Corollary 1 from LS18
        if !self.is_power_of_two_conductor() {
            return Err("Exact strong sampling only for power-of-two conductors".to_string());
        }

        let k = self.compute_k()?;
        let max_beta = self.compute_max_beta(k)?;

        if self.beta >= max_beta {
            return Err(format!(
                "Beta {} exceeds maximum {} for invertibility",
                self.beta, max_beta
            ));
        }

        // Generate all elements with ||c||_∞ ≤ β
        let elements = self.generate_bounded_elements()?;

        // Verify they form a strong sampling set
        self.verify_strong_sampling(&elements)?;

        let norm_bound = self.compute_operator_norm_bound();

        Ok(StrongSamplingSet {
            elements,
            norm_bound,
            non_unit_prob: 0.0, // Exact set
        })
    }

    fn is_power_of_two_conductor(&self) -> bool {
        let f = self.ring.conductor;
        f > 0 && (f & (f - 1)) == 0
    }

    fn compute_k(&self) -> Result<usize, String> {
        // Find largest k such that q = 2k + 1 (mod 4k)
        // and φ ≥ k > 1 where k is power of 2
        let phi = self.ring.degree;
        let q = self.ring.modulus.to_u64();

        let mut k = 2;
        while k <= phi {
            if (q % (4 * k) == 2 * k + 1) {
                return Ok(k);
            }
            k *= 2;
        }

        Err("Cannot find suitable k for exact strong sampling".to_string())
    }

    fn compute_max_beta(&self, k: usize) -> Result<usize, String> {
        // β < 1/√k · q^{1/k}
        let q = self.ring.modulus.to_u64() as f64;
        let k_f64 = k as f64;
        let max_beta = (1.0 / k_f64.sqrt()) * q.powf(1.0 / k_f64);
        Ok(max_beta.floor() as usize)
    }

    fn generate_bounded_elements(&self) -> Result<Vec<RingElement<F>>, String> {
        let mut elements = Vec::new();
        let range = (2 * self.beta + 1) as usize;
        
        // Generate all combinations of coefficients in [-β, β]
        self.generate_recursive(
            &mut vec![],
            0,
            &mut elements,
            range,
        );

        Ok(elements)
    }

    fn generate_recursive(
        &self,
        current: &mut Vec<F>,
        pos: usize,
        result: &mut Vec<RingElement<F>>,
        range: usize,
    ) {
        if pos == self.ring.degree {
            result.push(RingElement::new(current.clone(), self.ring.conductor));
            return;
        }

        let beta_i64 = self.beta as i64;
        for val in -beta_i64..=beta_i64 {
            current.push(F::from_i64(val));
            self.generate_recursive(current, pos + 1, result, range);
            current.pop();
        }
    }

    fn verify_strong_sampling(&self, elements: &[RingElement<F>]) -> Result<(), String> {
        // Verify that for all c1 ≠ c2, c1 - c2 is invertible
        // In practice, spot check due to combinatorial explosion
        for i in 0..elements.len().min(100) {
            for j in (i + 1)..elements.len().min(100) {
                let diff = self.ring.subtract(&elements[i], &elements[j]);
                if !self.ring.is_unit(&diff) {
                    return Err(format!(
                        "Non-invertible difference found at indices {}, {}",
                        i, j
                    ));
                }
            }
        }
        Ok(())
    }

    fn compute_operator_norm_bound(&self) -> F {
        // ||c||_op ≤ β · γ_∞ where γ_∞ is operator norm factor
        // For simplicity, use β · φ as upper bound
        let bound = self.beta * self.ring.degree;
        F::from_u64(bound as u64)
    }
}

/// Approximate Strong Sampling Set using biased ternary distribution (Lemma 8, 9)
pub struct ApproximateStrongSampling<F: FiniteField> {
    ring: CyclotomicRing<F>,
    /// Bias probability p for sampling 0
    bias_prob: f64,
}

impl<F: FiniteField> ApproximateStrongSampling<F> {
    pub fn new(ring: CyclotomicRing<F>, bias_prob: f64) -> Self {
        Self { ring, bias_prob }
    }

    /// Generate approximate strong sampling set
    /// Uses biased ternary distribution {-1, 0, 1}
    pub fn generate(&self) -> Result<StrongSamplingSet<F>, String> {
        // For uniform ternary (p = 1/3), all values equally likely
        if (self.bias_prob - 1.0/3.0).abs() < 1e-10 {
            return self.generate_uniform_ternary();
        }

        self.generate_biased_ternary()
    }

    fn generate_uniform_ternary(&self) -> Result<StrongSamplingSet<F>, String> {
        // Generate all ternary vectors
        let mut elements = Vec::new();
        self.generate_ternary_recursive(&mut vec![], 0, &mut elements);

        // Compute non-unit probability using Lemma 9
        let k = self.compute_splitting_degree()?;
        let kappa_nu = self.compute_non_unit_probability(k)?;

        let norm_bound = F::from_u64(self.ring.degree as u64);

        Ok(StrongSamplingSet {
            elements,
            norm_bound,
            non_unit_prob: kappa_nu,
        })
    }

    fn generate_biased_ternary(&self) -> Result<StrongSamplingSet<F>, String> {
        // Similar to uniform but with bias
        let mut elements = Vec::new();
        self.generate_ternary_recursive(&mut vec![], 0, &mut elements);

        let k = self.compute_splitting_degree()?;
        let kappa_nu = self.compute_biased_non_unit_probability(k)?;

        let norm_bound = F::from_u64(self.ring.degree as u64);

        Ok(StrongSamplingSet {
            elements,
            norm_bound,
            non_unit_prob: kappa_nu,
        })
    }

    fn generate_ternary_recursive(
        &self,
        current: &mut Vec<F>,
        pos: usize,
        result: &mut Vec<RingElement<F>>,
    ) {
        if pos == self.ring.degree {
            result.push(RingElement::new(current.clone(), self.ring.conductor));
            return;
        }

        for val in [-1, 0, 1] {
            current.push(F::from_i64(val));
            self.generate_ternary_recursive(current, pos + 1, result);
            current.pop();
        }
    }

    fn compute_splitting_degree(&self) -> Result<usize, String> {
        // Find k such that X^φ + 1 splits to degree φ/k polynomials
        // For NTT-friendly parameters: q ≡ 1 (mod 2k)
        let q = self.ring.modulus.to_u64();
        let phi = self.ring.degree;

        let mut k = 2;
        while k <= phi {
            if q % (2 * k) == 1 {
                return Ok(k);
            }
            k *= 2;
        }

        Ok(phi) // Default to no splitting
    }

    fn compute_non_unit_probability(&self, k: usize) -> Result<f64, String> {
        // From Lemma 9: κ_nu ≈ k / q^{φ/k}
        let q = self.ring.modulus.to_u64() as f64;
        let phi = self.ring.degree as f64;
        let k_f64 = k as f64;

        let kappa = k_f64 / q.powf(phi / k_f64);
        Ok(kappa)
    }

    fn compute_biased_non_unit_probability(&self, k: usize) -> Result<f64, String> {
        // Adjusted for bias using well-spread analysis (Lemma 8)
        let base_prob = self.compute_non_unit_probability(k)?;
        
        // Bias adjustment factor
        let p = self.bias_prob;
        let adjustment = (1.0 - p) / (2.0/3.0); // Relative to uniform
        
        Ok(base_prob * adjustment)
    }
}

/// Build strong sampling set from parameters
pub fn build_strong_sampling_set<F: FiniteField>(
    ring: CyclotomicRing<F>,
    use_exact: bool,
    beta: Option<usize>,
    bias_prob: Option<f64>,
) -> Result<StrongSamplingSet<F>, String> {
    
    if use_exact {
        let beta = beta.ok_or("Beta required for exact strong sampling")?;
        let builder = ExactStrongSampling::new(ring, beta);
        builder.generate()
    } else {
        let bias = bias_prob.unwrap_or(1.0 / 3.0);
        let builder = ApproximateStrongSampling::new(ring, bias);
        builder.generate()
    }
}

/// Ternary distribution sampler
pub struct TernaryDistribution {
    /// Probability of sampling 0
    pub prob_zero: f64,
}

impl TernaryDistribution {
    pub fn uniform() -> Self {
        Self { prob_zero: 1.0 / 3.0 }
    }

    pub fn biased(prob_zero: f64) -> Self {
        Self { prob_zero }
    }

    pub fn sample<F: FiniteField>(&self, rng: &mut impl rand::Rng) -> F {
        let r: f64 = rng.gen();
        
        if r < self.prob_zero {
            F::zero()
        } else if r < self.prob_zero + (1.0 - self.prob_zero) / 2.0 {
            F::one()
        } else {
            F::one().neg()
        }
    }

    pub fn sample_vector<F: FiniteField>(
        &self,
        length: usize,
        rng: &mut impl rand::Rng,
    ) -> Vec<F> {
        (0..length).map(|_| self.sample(rng)).collect()
    }

    pub fn sample_ring_element<F: FiniteField>(
        &self,
        conductor: usize,
        rng: &mut impl rand::Rng,
    ) -> RingElement<F> {
        let degree = euler_totient(conductor);
        let coeffs = self.sample_vector(degree, rng);
        RingElement::new(coeffs, conductor)
    }
}
