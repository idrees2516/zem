// Sumcheck prover over extension fields F_{q^k}
//
// Implements the prover side of the sumcheck protocol,
// computing univariate polynomials for each round.

use crate::hachi::errors::HachiError;
use crate::hachi::params::HachiParams;
use crate::field::Field;

/// Sumcheck prover over extension field F_{q^k}
///
/// For multilinear polynomial P ∈ F_{q^k}^{≤1}[X_1, ..., X_μ] and
/// public polynomial Q ∈ F_{q^k}^{≤1}[X_1, ..., X_μ],
/// prove: Σ_{i∈{0,1}^μ} P(i) · Q(i) = V
///
/// Protocol:
/// - Round j: Prover sends univariate g_j(X) = Σ_{b∈{0,1}^{μ-j}} P(r_{<j}, X, b) · Q(r_{<j}, X, b)
/// - Verifier checks g_j(0) + g_j(1) = previous sum
/// - Verifier sends challenge r_j
/// - Final: Prover sends P(r_1, ..., r_μ)
#[derive(Clone, Debug)]
pub struct SumcheckProver<F: Field> {
    /// Number of variables μ
    num_variables: usize,
    
    /// Ring dimension (for field operations)
    ring_dimension: usize,
}

impl<F: Field> SumcheckProver<F> {
    /// Create a new sumcheck prover
    pub fn new(params: &HachiParams<F>, num_variables: usize) -> Result<Self, HachiError> {
        let ring_dimension = params.ring_dimension();
        
        Ok(Self {
            num_variables,
            ring_dimension,
        })
    }
    
    /// Compute univariate polynomial for round j
    ///
    /// g_j(X) = Σ_{b∈{0,1}^{μ-j}} P(r_{<j}, X, b) · Q(r_{<j}, X, b)
    pub fn compute_round_polynomial(
        &self,
        p_values: &[F],
        q_values: &[F],
        round: usize,
        previous_challenges: &[F],
    ) -> Result<Vec<F>, HachiError> {
        if p_values.len() != q_values.len() {
            return Err(HachiError::InvalidDimension {
                expected: p_values.len(),
                actual: q_values.len(),
            });
        }
        
        let remaining_vars = self.num_variables - round;
        let remaining_size = 1 << remaining_vars;
        
        if p_values.len() != remaining_size {
            return Err(HachiError::InvalidDimension {
                expected: remaining_size,
                actual: p_values.len(),
            });
        }
        
        // Compute univariate polynomial g_j(X)
        // Degree is at most 2 (since P and Q are multilinear)
        let mut g = vec![F::zero(); 3];
        
        // For each evaluation point in {0, 1}
        for x in 0..2 {
            let x_field = F::from_u64(x as u64);
            
            // Compute g_j(x) = Σ_{b∈{0,1}^{μ-j-1}} P(r_{<j}, x, b) · Q(r_{<j}, x, b)
            let mut sum = F::zero();
            
            for b in 0..remaining_size / 2 {
                // Compute indices for P and Q
                let idx0 = (x << (remaining_vars - 1)) | b;
                let idx1 = ((1 - x) << (remaining_vars - 1)) | b;
                
                if idx0 < p_values.len() && idx1 < q_values.len() {
                    let term = p_values[idx0] * q_values[idx0];
                    sum = sum + term;
                }
            }
            
            g[x] = sum;
        }
        
        // Compute g_j(2) for degree 2 polynomial
        // Using Lagrange interpolation or direct computation
        g[2] = self.compute_polynomial_at_point(&g, F::from_u64(2))?;
        
        Ok(g)
    }
    
    /// Compute polynomial value at arbitrary point
    fn compute_polynomial_at_point(&self, coeffs: &[F], point: F) -> Result<F, HachiError> {
        let mut result = F::zero();
        let mut power = F::one();
        
        for &coeff in coeffs {
            result = result + (coeff * power);
            power = power * point;
        }
        
        Ok(result)
    }
    
    /// Reduce to next round
    ///
    /// Given challenge r_j, compute reduced P and Q for next round
    pub fn reduce_to_next_round(
        &self,
        p_values: &[F],
        q_values: &[F],
        challenge: F,
    ) -> Result<(Vec<F>, Vec<F>), HachiError> {
        if p_values.len() != q_values.len() {
            return Err(HachiError::InvalidDimension {
                expected: p_values.len(),
                actual: q_values.len(),
            });
        }
        
        let size = p_values.len();
        if size & (size - 1) != 0 {
            return Err(HachiError::InvalidParameters(
                format!("Size {} must be power of 2", size)
            ));
        }
        
        let half_size = size / 2;
        let mut reduced_p = Vec::with_capacity(half_size);
        let mut reduced_q = Vec::with_capacity(half_size);
        
        // For each index in reduced space
        for i in 0..half_size {
            // Compute reduced value: (1-r)·v_0 + r·v_1
            let one = F::one();
            let one_minus_r = one - challenge;
            
            let p_reduced = (one_minus_r * p_values[i]) + (challenge * p_values[half_size + i]);
            let q_reduced = (one_minus_r * q_values[i]) + (challenge * q_values[half_size + i]);
            
            reduced_p.push(p_reduced);
            reduced_q.push(q_reduced);
        }
        
        Ok((reduced_p, reduced_q))
    }
    
    /// Compute final evaluation
    ///
    /// After all rounds, compute P(r_1, ..., r_μ)
    pub fn compute_final_evaluation(
        &self,
        p_values: &[F],
    ) -> Result<F, HachiError> {
        if p_values.len() != 1 {
            return Err(HachiError::InvalidDimension {
                expected: 1,
                actual: p_values.len(),
            });
        }
        
        Ok(p_values[0])
    }
}

/// Sumcheck proof structure
#[derive(Clone, Debug)]
pub struct SumcheckProof<F: Field> {
    /// Univariate polynomials for each round
    pub round_polynomials: Vec<Vec<F>>,
    
    /// Final evaluation P(r_1, ..., r_μ)
    pub final_evaluation: F,
    
    /// Challenges used
    pub challenges: Vec<F>,
}

impl<F: Field> SumcheckProof<F> {
    /// Create new sumcheck proof
    pub fn new(
        round_polynomials: Vec<Vec<F>>,
        final_evaluation: F,
        challenges: Vec<F>,
    ) -> Self {
        Self {
            round_polynomials,
            final_evaluation,
            challenges,
        }
    }
    
    /// Get number of rounds
    pub fn num_rounds(&self) -> usize {
        self.round_polynomials.len()
    }
    
    /// Get round polynomial
    pub fn round_polynomial(&self, round: usize) -> Option<&[F]> {
        self.round_polynomials.get(round).map(|v| v.as_slice())
    }
    
    /// Get final evaluation
    pub fn final_evaluation(&self) -> F {
        self.final_evaluation
    }
    
    /// Get challenges
    pub fn challenges(&self) -> &[F] {
        &self.challenges
    }
}

/// Interactive sumcheck prover
pub struct InteractiveSumcheckProver<F: Field> {
    prover: SumcheckProver<F>,
    
    /// Current P values
    current_p: Vec<F>,
    
    /// Current Q values
    current_q: Vec<F>,
    
    /// Current round
    current_round: usize,
    
    /// Accumulated challenges
    challenges: Vec<F>,
    
    /// Round polynomials
    round_polynomials: Vec<Vec<F>>,
}

impl<F: Field> InteractiveSumcheckProver<F> {
    /// Create interactive prover
    pub fn new(
        params: &HachiParams<F>,
        num_variables: usize,
        p_values: Vec<F>,
        q_values: Vec<F>,
    ) -> Result<Self, HachiError> {
        let prover = SumcheckProver::new(params, num_variables)?;
        
        Ok(Self {
            prover,
            current_p: p_values,
            current_q: q_values,
            current_round: 0,
            challenges: Vec::new(),
            round_polynomials: Vec::new(),
        })
    }
    
    /// Execute next round
    pub fn next_round(&mut self) -> Result<Vec<F>, HachiError> {
        let poly = self.prover.compute_round_polynomial(
            &self.current_p,
            &self.current_q,
            self.current_round,
            &self.challenges,
        )?;
        
        self.round_polynomials.push(poly.clone());
        self.current_round += 1;
        
        Ok(poly)
    }
    
    /// Receive challenge and reduce
    pub fn receive_challenge(&mut self, challenge: F) -> Result<(), HachiError> {
        let (reduced_p, reduced_q) = self.prover.reduce_to_next_round(
            &self.current_p,
            &self.current_q,
            challenge,
        )?;
        
        self.current_p = reduced_p;
        self.current_q = reduced_q;
        self.challenges.push(challenge);
        
        Ok(())
    }
    
    /// Get final evaluation
    pub fn finalize(&self) -> Result<F, HachiError> {
        self.prover.compute_final_evaluation(&self.current_p)
    }
    
    /// Get proof
    pub fn get_proof(&self) -> Result<SumcheckProof<F>, HachiError> {
        let final_eval = self.finalize()?;
        
        Ok(SumcheckProof::new(
            self.round_polynomials.clone(),
            final_eval,
            self.challenges.clone(),
        ))
    }
}

/// Batch sumcheck prover
pub struct BatchSumcheckProver<F: Field> {
    prover: SumcheckProver<F>,
}

impl<F: Field> BatchSumcheckProver<F> {
    pub fn new(params: &HachiParams<F>, num_variables: usize) -> Result<Self, HachiError> {
        let prover = SumcheckProver::new(params, num_variables)?;
        Ok(Self { prover })
    }
    
    /// Prove multiple sumcheck claims
    pub fn batch_prove(
        &self,
        claims: &[SumcheckClaim<F>],
    ) -> Result<Vec<SumcheckProof<F>>, HachiError> {
        claims.iter()
            .map(|claim| self.prove_single(claim))
            .collect()
    }
    
    /// Prove single claim
    fn prove_single(&self, claim: &SumcheckClaim<F>) -> Result<SumcheckProof<F>, HachiError> {
        let mut round_polynomials = Vec::new();
        let mut current_p = claim.p_values.clone();
        let mut current_q = claim.q_values.clone();
        let mut challenges = Vec::new();
        
        for round in 0..self.prover.num_variables {
            // Compute round polynomial
            let poly = self.prover.compute_round_polynomial(
                &current_p,
                &current_q,
                round,
                &challenges,
            )?;
            
            round_polynomials.push(poly);
            
            // Generate challenge (in real protocol, from verifier)
            let challenge = F::from_u64((round as u64) + 1);
            challenges.push(challenge);
            
            // Reduce to next round
            let (reduced_p, reduced_q) = self.prover.reduce_to_next_round(
                &current_p,
                &current_q,
                challenge,
            )?;
            
            current_p = reduced_p;
            current_q = reduced_q;
        }
        
        let final_eval = self.prover.compute_final_evaluation(&current_p)?;
        
        Ok(SumcheckProof::new(round_polynomials, final_eval, challenges))
    }
}

/// Sumcheck claim
#[derive(Clone, Debug)]
pub struct SumcheckClaim<F: Field> {
    pub p_values: Vec<F>,
    pub q_values: Vec<F>,
    pub target: F,
    pub num_variables: usize,
}

impl<F: Field> SumcheckClaim<F> {
    pub fn new(p_values: Vec<F>, q_values: Vec<F>, target: F) -> Result<Self, HachiError> {
        if p_values.len() != q_values.len() {
            return Err(HachiError::InvalidDimension {
                expected: p_values.len(),
                actual: q_values.len(),
            });
        }
        
        let size = p_values.len();
        let num_variables = (size as f64).log2() as usize;
        
        if 1 << num_variables != size {
            return Err(HachiError::InvalidParameters(
                format!("Size {} must be power of 2", size)
            ));
        }
        
        Ok(Self {
            p_values,
            q_values,
            target,
            num_variables,
        })
    }
}
