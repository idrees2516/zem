// Sum-Check Protocol Implementation
// Implements NEO-9 requirements for sum-check prover and verifier

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use std::marker::PhantomData;

/// Univariate polynomial represented by evaluations at points 0, 1, ..., d
#[derive(Clone, Debug)]
pub struct UnivariatePolynomial<F: Field> {
    /// Evaluations at points 0, 1, ..., degree
    pub evaluations: Vec<F>,
}

impl<F: Field> UnivariatePolynomial<F> {
    /// Create from evaluations
    pub fn new(evaluations: Vec<F>) -> Self {
        Self { evaluations }
    }

    /// Get degree
    pub fn degree(&self) -> usize {
        self.evaluations.len().saturating_sub(1)
    }

    /// Evaluate at a point using Lagrange interpolation
    pub fn evaluate(&self, point: F) -> F {
        let d = self.degree();
        let mut result = F::zero();

        for (i, &eval_i) in self.evaluations.iter().enumerate() {
            // Compute Lagrange basis polynomial L_i(point)
            let mut basis = F::one();
            
            for j in 0..=d {
                if i != j {
                    // basis *= (point - j) / (i - j)
                    let numerator = point.sub(&F::from_u64(j as u64));
                    let denominator = F::from_u64(i as u64).sub(&F::from_u64(j as u64));
                    let denom_inv = denominator.inv().expect("Denominator should be non-zero");
                    basis = basis.mul(&numerator).mul(&denom_inv);
                }
            }
            
            result = result.add(&eval_i.mul(&basis));
        }

        result
    }

    /// Evaluate at 0
    pub fn eval_at_zero(&self) -> F {
        self.evaluations[0]
    }

    /// Evaluate at 1
    pub fn eval_at_one(&self) -> F {
        if self.evaluations.len() > 1 {
            self.evaluations[1]
        } else {
            F::zero()
        }
    }
}

/// Sum-check proof for a single round
#[derive(Clone, Debug)]
pub struct SumCheckRound<F: Field> {
    /// Univariate polynomial s_i(X) represented by evaluations
    pub polynomial: UnivariatePolynomial<F>,
    /// Challenge r_i sampled by verifier
    pub challenge: F,
}

/// Complete sum-check proof
#[derive(Clone, Debug)]
pub struct SumCheckProof<F: Field> {
    /// Rounds of the protocol (one per variable)
    pub rounds: Vec<SumCheckRound<F>>,
    /// Final evaluation g(r_1, ..., r_ℓ)
    pub final_evaluation: F,
}

/// Sum-check prover for polynomial g: F^ℓ → F
pub struct SumCheckProver<F: Field> {
    /// Number of variables
    num_vars: usize,
    /// Maximum degree of polynomial
    max_degree: usize,
    /// Current round (0-indexed)
    current_round: usize,
    /// Challenges received so far
    challenges: Vec<F>,
    _phantom: PhantomData<F>,
}

impl<F: Field> SumCheckProver<F> {
    /// Create a new sum-check prover
    pub fn new(num_vars: usize, max_degree: usize) -> Self {
        Self {
            num_vars,
            max_degree,
            current_round: 0,
            challenges: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Compute round i polynomial s_i(X)
    /// s_i(X) = Σ_{x∈{0,1}^{ℓ-i}} g(r_1,...,r_{i-1},X,x)
    pub fn compute_round_polynomial<G>(
        &self,
        eval_fn: &G,
    ) -> UnivariatePolynomial<F>
    where
        G: Fn(&[F]) -> F,
    {
        let remaining_vars = self.num_vars - self.current_round - 1;
        let num_evals = 1 << remaining_vars;
        
        let mut evaluations = Vec::with_capacity(self.max_degree + 1);

        // Evaluate s_i at points 0, 1, ..., max_degree
        for eval_point in 0..=self.max_degree {
            let mut sum = F::zero();
            
            // Sum over all Boolean assignments to remaining variables
            for assignment in 0..num_evals {
                // Build full evaluation point: (r_1, ..., r_{i-1}, eval_point, x)
                let mut point = self.challenges.clone();
                point.push(F::from_u64(eval_point as u64));
                
                // Add remaining variable assignments
                for j in 0..remaining_vars {
                    let bit = (assignment >> j) & 1;
                    point.push(F::from_u64(bit as u64));
                }
                
                sum = sum.add(&eval_fn(&point));
            }
            
            evaluations.push(sum);
        }

        UnivariatePolynomial::new(evaluations)
    }

    /// Process verifier's challenge for current round
    pub fn receive_challenge(&mut self, challenge: F) {
        self.challenges.push(challenge);
        self.current_round += 1;
    }

    /// Check if protocol is complete
    pub fn is_complete(&self) -> bool {
        self.current_round >= self.num_vars
    }

    /// Get current round number
    pub fn current_round(&self) -> usize {
        self.current_round
    }

    /// Get challenges received so far
    pub fn challenges(&self) -> &[F] {
        &self.challenges
    }
}

/// Sum-check verifier
pub struct SumCheckVerifier<F: Field> {
    /// Number of variables
    num_vars: usize,
    /// Maximum degree
    max_degree: usize,
    /// Claimed sum H
    claimed_sum: F,
    /// Current round
    current_round: usize,
    /// Previous round polynomial evaluation at challenge
    previous_eval: F,
    /// Challenges generated
    challenges: Vec<F>,
}

impl<F: Field> SumCheckVerifier<F> {
    /// Create a new sum-check verifier
    pub fn new(num_vars: usize, max_degree: usize, claimed_sum: F) -> Self {
        Self {
            num_vars,
            max_degree,
            claimed_sum,
            current_round: 0,
            previous_eval: claimed_sum,
            challenges: Vec::new(),
        }
    }

    /// Verify a round polynomial and generate challenge
    pub fn verify_round(
        &mut self,
        polynomial: &UnivariatePolynomial<F>,
        challenge: F,
    ) -> Result<(), String> {
        if self.current_round >= self.num_vars {
            return Err("All rounds already completed".to_string());
        }

        // Check degree
        if polynomial.degree() > self.max_degree {
            return Err(format!(
                "Polynomial degree {} exceeds maximum {}",
                polynomial.degree(),
                self.max_degree
            ));
        }

        // Verify consistency check: s_i(0) + s_i(1) = H (round 0) or s_{i-1}(r_{i-1})
        let sum = polynomial.eval_at_zero().add(&polynomial.eval_at_one());
        
        if self.current_round == 0 {
            if sum != self.claimed_sum {
                return Err(format!(
                    "Round 0 check failed: s_0(0) + s_0(1) = {:?}, expected {:?}",
                    sum, self.claimed_sum
                ));
            }
        } else {
            if sum != self.previous_eval {
                return Err(format!(
                    "Round {} check failed: s_i(0) + s_i(1) = {:?}, expected {:?}",
                    self.current_round, sum, self.previous_eval
                ));
            }
        }

        // Evaluate polynomial at challenge point
        let eval_at_challenge = polynomial.evaluate(challenge);
        
        // Update state
        self.previous_eval = eval_at_challenge;
        self.challenges.push(challenge);
        self.current_round += 1;

        Ok(())
    }

    /// Perform final verification
    pub fn final_verify(&self, final_evaluation: F) -> Result<bool, String> {
        if self.current_round != self.num_vars {
            return Err(format!(
                "Protocol not complete: {} rounds done, expected {}",
                self.current_round, self.num_vars
            ));
        }

        // Check that g(r_1, ..., r_ℓ) = s_ℓ(r_ℓ)
        Ok(final_evaluation == self.previous_eval)
    }

    /// Get challenges generated so far
    pub fn challenges(&self) -> &[F] {
        &self.challenges
    }

    /// Check if protocol is complete
    pub fn is_complete(&self) -> bool {
        self.current_round >= self.num_vars
    }
}

/// Run complete sum-check protocol
pub fn run_sumcheck<F: Field, G>(
    num_vars: usize,
    max_degree: usize,
    claimed_sum: F,
    eval_fn: G,
    challenge_fn: impl Fn(usize) -> F,
) -> Result<SumCheckProof<F>, String>
where
    G: Fn(&[F]) -> F,
{
    let mut prover = SumCheckProver::new(num_vars, max_degree);
    let mut verifier = SumCheckVerifier::new(num_vars, max_degree, claimed_sum);
    let mut rounds = Vec::new();

    // Run ℓ rounds
    for round in 0..num_vars {
        // Prover computes round polynomial
        let polynomial = prover.compute_round_polynomial(&eval_fn);
        
        // Generate challenge
        let challenge = challenge_fn(round);
        
        // Verifier checks and accepts challenge
        verifier.verify_round(&polynomial, challenge)?;
        
        // Prover receives challenge
        prover.receive_challenge(challenge);
        
        rounds.push(SumCheckRound {
            polynomial,
            challenge,
        });
    }

    // Final evaluation
    let final_point = prover.challenges();
    let final_evaluation = eval_fn(final_point);
    
    // Verifier performs final check
    if !verifier.final_verify(final_evaluation)? {
        return Err("Final verification failed".to_string());
    }

    Ok(SumCheckProof {
        rounds,
        final_evaluation,
    })
}

/// Optimized sum-check for multilinear polynomials
pub struct MultilinearSumCheck<F: Field> {
    mle: MultilinearPolynomial<F>,
}

impl<F: Field> MultilinearSumCheck<F> {
    /// Create from multilinear polynomial
    pub fn new(mle: MultilinearPolynomial<F>) -> Self {
        Self { mle }
    }

    /// Compute sum over Boolean hypercube: Σ_{x∈{0,1}^ℓ} f(x)
    pub fn compute_sum(&self) -> F {
        self.mle.evaluations().iter().fold(F::zero(), |acc, &x| acc.add(&x))
    }

    /// Run sum-check protocol with optimized prover
    pub fn prove(
        &self,
        challenge_fn: impl Fn(usize) -> F,
    ) -> Result<SumCheckProof<F>, String> {
        let num_vars = self.mle.num_vars();
        let claimed_sum = self.compute_sum();
        
        // For multilinear polynomials, degree is always 1
        let max_degree = 1;
        
        let eval_fn = |point: &[F]| self.mle.evaluate(point);
        
        run_sumcheck(num_vars, max_degree, claimed_sum, eval_fn, challenge_fn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;

    #[test]
    fn test_univariate_polynomial_eval() {
        type F = GoldilocksField;
        
        // Polynomial: 1 + 2X (evaluations at 0, 1: [1, 3])
        let poly = UnivariatePolynomial::new(vec![
            F::from_u64(1),
            F::from_u64(3),
        ]);
        
        // Evaluate at X = 2: should be 1 + 2*2 = 5
        let result = poly.evaluate(F::from_u64(2));
        assert_eq!(result, F::from_u64(5));
    }

    #[test]
    fn test_sumcheck_simple() {
        type F = GoldilocksField;
        
        // Simple polynomial: f(x, y) = x + y
        // Over {0,1}^2: f(0,0)=0, f(0,1)=1, f(1,0)=1, f(1,1)=2
        // Sum = 0 + 1 + 1 + 2 = 4
        let eval_fn = |point: &[F]| {
            assert_eq!(point.len(), 2);
            point[0].add(&point[1])
        };
        
        let claimed_sum = F::from_u64(4);
        
        // Use deterministic challenges for testing
        let challenge_fn = |round: usize| F::from_u64((round + 2) as u64);
        
        let proof = run_sumcheck(2, 1, claimed_sum, eval_fn, challenge_fn);
        assert!(proof.is_ok());
    }

    #[test]
    fn test_multilinear_sumcheck() {
        type F = GoldilocksField;
        
        // MLE of [1, 2, 3, 4]
        let evaluations = vec![
            F::from_u64(1),
            F::from_u64(2),
            F::from_u64(3),
            F::from_u64(4),
        ];
        
        let mle = MultilinearPolynomial::new(evaluations);
        let sumcheck = MultilinearSumCheck::new(mle);
        
        // Sum should be 1 + 2 + 3 + 4 = 10
        let sum = sumcheck.compute_sum();
        assert_eq!(sum, F::from_u64(10));
        
        // Run sum-check protocol
        let challenge_fn = |round: usize| F::from_u64((round + 1) as u64);
        let proof = sumcheck.prove(challenge_fn);
        assert!(proof.is_ok());
    }

    #[test]
    fn test_verifier_rejects_wrong_sum() {
        type F = GoldilocksField;
        
        let eval_fn = |point: &[F]| {
            assert_eq!(point.len(), 2);
            point[0].add(&point[1])
        };
        
        // Wrong claimed sum (should be 4, claiming 5)
        let wrong_sum = F::from_u64(5);
        let challenge_fn = |round: usize| F::from_u64((round + 2) as u64);
        
        let proof = run_sumcheck(2, 1, wrong_sum, eval_fn, challenge_fn);
        assert!(proof.is_err());
    }
}
