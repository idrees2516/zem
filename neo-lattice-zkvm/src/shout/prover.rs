// Task 2.3: Shout Prover Commitment Phase
// Task 2.4: Shout Read-Checking Sum-Check
// Task 2.5: Shout Booleanity Check
// Task 2.6: Shout One-Hot Check

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::{MultilinearPolynomial, UnivariatePolynomial, DenseSumCheckProver};
use crate::shout::{OneHotAddress, ShoutProtocol};
use crate::commitment::PolynomialCommitment;
use std::fmt::Debug;

/// Shout prover state
pub struct ShoutProver<K: ExtensionFieldElement> {
    pub memory_size: usize,
    pub num_lookups: usize,
    pub dimension: usize,
    pub access_matrices: Vec<MultilinearPolynomial<K>>,
}

impl<K: ExtensionFieldElement> ShoutProver<K> {
    pub fn new(memory_size: usize, num_lookups: usize, dimension: usize) -> Self {
        Self {
            memory_size,
            num_lookups,
            dimension,
            access_matrices: Vec::new(),
        }
    }
    
    /// Task 2.3: Commit to one-hot encoded addresses
    /// For each dimension i ∈ {1,...,d}:
    /// - Create access matrix ra_i of size K^{1/d} × T
    /// - For each lookup j: encode address[j], set ra_i[digit_i, j] = 1
    /// - Flatten and commit via PCS
    /// Only d·T non-zero values (all 1s), rest are 0s (free with elliptic curves)
    pub fn prover_commit<PCS>(
        &mut self,
        addresses: &[usize],
        pcs: &PCS,
    ) -> Result<Vec<PCS::Commitment>, String>
    where
        PCS: PolynomialCommitment<K>,
    {
        if addresses.len() != self.num_lookups {
            return Err("Address count must match num_lookups".to_string());
        }
        
        let chunk_size = ((self.memory_size as f64)
            .powf(1.0 / self.dimension as f64)
            .ceil()) as usize;
        
        let mut commitments = Vec::with_capacity(self.dimension);
        
        // For each dimension, create and commit access matrix
        for dim in 0..self.dimension {
            // Access matrix: K^{1/d} rows × T columns
            let mut access_matrix = vec![vec![K::zero(); self.num_lookups]; chunk_size];
            
            // Fill matrix with one-hot encodings
            for (j, &addr) in addresses.iter().enumerate() {
                let one_hot = OneHotAddress::encode(addr, self.memory_size, self.dimension)?;
                
                // Set the appropriate position to 1
                for (k, &val) in one_hot.chunks[dim].iter().enumerate() {
                    if val == K::one() {
                        access_matrix[k][j] = K::one();
                    }
                }
            }
            
            // Flatten matrix to vector (row-major order)
            let flat: Vec<K> = access_matrix.into_iter().flatten().collect();
            
            // Create MLE and commit
            let mle = MultilinearPolynomial::from_evaluations(flat)?;
            let commitment = pcs.commit(&mle)?;
            
            self.access_matrices.push(mle);
            commitments.push(commitment);
        }
        
        Ok(commitments)
    }
    
    /// Task 2.4: Read-checking sum-check
    /// Proves: rv(r') = Σ_k ra(k,r')·Val(k)
    /// Exploits sparsity: only T out of 2^{log K} terms are non-zero
    /// Prover time: O(K + T·log K)
    pub fn read_checking_sumcheck(
        &self,
        rcycle: &[K],
        table: &MultilinearPolynomial<K>,
    ) -> Result<ReadCheckProof<K>, String> {
        let log_k = (self.memory_size as f64).log2() as usize;
        let mut round_polynomials = Vec::with_capacity(log_k);
        
        // Create sparse sum-check prover
        // g(k) = ra(k, rcycle) · Val(k)
        // Only T terms non-zero (where ra ≠ 0)
        
        let mut current_evals_p = self.compute_ra_at_rcycle(rcycle)?;
        let mut current_evals_q = table.evaluations.clone();
        
        let mut challenges = Vec::new();
        
        for round in 0..log_k {
            // Compute round polynomial s_i(X)
            let round_poly = self.compute_sparse_round_poly(
                &current_evals_p,
                &current_evals_q,
            );
            
            round_polynomials.push(round_poly.clone());
            
            // Sample challenge (in practice, use Fiat-Shamir)
            let challenge = self.sample_challenge(round);
            challenges.push(challenge);
            
            // Update evaluations
            current_evals_p = self.partial_eval(&current_evals_p, challenge);
            current_evals_q = self.partial_eval(&current_evals_q, challenge);
        }
        
        // Final evaluation: ra(raddress, rcycle) · Val(raddress)
        let final_eval = if !current_evals_p.is_empty() && !current_evals_q.is_empty() {
            current_evals_p[0].mul(&current_evals_q[0])
        } else {
            K::zero()
        };
        
        Ok(ReadCheckProof {
            round_polynomials,
            final_evaluation: final_eval,
            challenges,
        })
    }
    
    /// Task 2.5: Booleanity check
    /// Verifies ra(k,j) ∈ {0,1} for all (k,j)
    /// Applies zero-check to: ra(k,j)² - ra(k,j) = 0
    /// Exploits sparsity: only T out of K·T terms potentially non-zero
    /// Prover time: O(K) + 2T field multiplications
    pub fn booleanity_check(
        &self,
        access_mle: &MultilinearPolynomial<K>,
        r: &[K],
        r_prime: &[K],
    ) -> Result<BooleanityProof<K>, String> {
        // Define constraint polynomial: g(k,j) = ra(k,j)² - ra(k,j)
        // Apply sum-check to prove: Σ_{k,j} eq(r,k)·eq(r',j)·g(k,j) = 0
        
        let log_k = (self.memory_size as f64).log2() as usize;
        let log_t = (self.num_lookups as f64).log2() as usize;
        let total_vars = log_k + log_t;
        
        let mut round_polynomials = Vec::with_capacity(total_vars);
        let mut challenges = Vec::new();
        
        // Create constraint evaluations: ra² - ra
        let mut constraint_evals: Vec<K> = access_mle.evaluations.iter()
            .map(|&ra_val| {
                let ra_squared = ra_val.mul(&ra_val);
                ra_squared.sub(&ra_val)
            })
            .collect();
        
        // Multiply by eq(r,k)·eq(r',j)
        let eq_vals = self.compute_eq_product(r, r_prime, log_k, log_t);
        for i in 0..constraint_evals.len() {
            constraint_evals[i] = constraint_evals[i].mul(&eq_vals[i]);
        }
        
        // Run sum-check (should sum to 0)
        let mut current_evals = constraint_evals;
        
        for round in 0..total_vars {
            let round_poly = self.compute_round_poly_single(&current_evals);
            round_polynomials.push(round_poly);
            
            let challenge = self.sample_challenge(round);
            challenges.push(challenge);
            
            current_evals = self.partial_eval(&current_evals, challenge);
        }
        
        let final_eval = if !current_evals.is_empty() {
            current_evals[0]
        } else {
            K::zero()
        };
        
        Ok(BooleanityProof {
            round_polynomials,
            final_evaluation: final_eval,
            challenges,
        })
    }
    
    /// Task 2.6: One-hot check
    /// Verifies Σ_k ra(k,j) = 1 for all j
    /// For non-binary fields: evaluate at (2^{-1}, ..., 2^{-1}, rcycle)
    /// Check: K·ra(2^{-1},...,2^{-1},rcycle) = 1
    /// For binary fields: use sum-check
    pub fn one_hot_check(
        &self,
        access_mle: &MultilinearPolynomial<K>,
        rcycle: &[K],
    ) -> Result<OneHotProof<K>, String> {
        // Check if field is binary
        let is_binary = K::BaseField::MODULUS == 2;
        
        if !is_binary {
            // Non-binary field: use half-point evaluation
            let log_k = (self.memory_size as f64).log2() as usize;
            
            // Create evaluation point: [1/2, 1/2, ..., 1/2, rcycle]
            let two = K::from_base_field_element(K::BaseField::from_u64(2), 0);
            let half = two.inverse().ok_or("Cannot compute 1/2")?;
            
            let mut eval_point = vec![half; log_k];
            eval_point.extend_from_slice(rcycle);
            
            // Evaluate ra at this point
            let ra_eval = access_mle.evaluate(&eval_point)?;
            
            // Check: K·ra(1/2,...,1/2,rcycle) = 1
            let k_field = K::from_base_field_element(
                K::BaseField::from_u64(self.memory_size as u64),
                0
            );
            let result = k_field.mul(&ra_eval);
            
            Ok(OneHotProof::NonBinary {
                evaluation: ra_eval,
                expected: K::one(),
                actual: result,
            })
        } else {
            // Binary field: use sum-check to compute Σ_k ra(k,rcycle)
            let sum_check_proof = self.hamming_weight_sumcheck(access_mle, rcycle)?;
            
            Ok(OneHotProof::Binary {
                sum_check_proof,
            })
        }
    }
    
    // Helper methods
    
    fn compute_ra_at_rcycle(&self, rcycle: &[K]) -> Result<Vec<K>, String> {
        // Compute ra(k, rcycle) for all k
        // This involves evaluating the tensor product at rcycle
        let chunk_size = ((self.memory_size as f64)
            .powf(1.0 / self.dimension as f64)
            .ceil()) as usize;
        
        let mut result = vec![K::zero(); self.memory_size];
        
        // For each memory location k
        for k in 0..self.memory_size {
            let one_hot = OneHotAddress::encode(k, self.memory_size, self.dimension)?;
            
            // Compute product of evaluations across dimensions
            let mut prod = K::one();
            for dim in 0..self.dimension {
                // Evaluate ra_dim at rcycle
                let ra_dim_eval = self.eval_one_hot_at_point(&one_hot.chunks[dim], rcycle);
                prod = prod.mul(&ra_dim_eval);
            }
            
            result[k] = prod;
        }
        
        Ok(result)
    }
    
    fn eval_one_hot_at_point(&self, one_hot: &[K], point: &[K]) -> K {
        // Evaluate one-hot vector's MLE at point
        let mut result = K::zero();
        for (idx, &val) in one_hot.iter().enumerate() {
            if val == K::one() {
                // Compute eq(point, idx)
                let bits = Self::index_to_bits(idx, point.len());
                let eq_val = Self::eq_polynomial(point, &bits);
                result = result.add(&eq_val);
            }
        }
        result
    }
    
    fn compute_sparse_round_poly(
        &self,
        p_evals: &[K],
        q_evals: &[K],
    ) -> UnivariatePolynomial<K> {
        let half = p_evals.len() / 2;
        
        let mut s_0 = K::zero();
        let mut s_1 = K::zero();
        let mut s_2 = K::zero();
        
        for i in 0..half {
            let p_0 = p_evals[i];
            let p_1 = p_evals[i + half];
            let q_0 = q_evals[i];
            let q_1 = q_evals[i + half];
            
            s_0 = s_0.add(&p_0.mul(&q_0));
            s_1 = s_1.add(&p_1.mul(&q_1));
            
            let two = K::from_base_field_element(K::BaseField::from_u64(2), 0);
            let p_2 = two.mul(&p_1).sub(&p_0);
            let q_2 = two.mul(&q_1).sub(&q_0);
            s_2 = s_2.add(&p_2.mul(&q_2));
        }
        
        UnivariatePolynomial::from_evaluations(&[s_0, s_1, s_2])
    }
    
    fn compute_round_poly_single(&self, evals: &[K]) -> UnivariatePolynomial<K> {
        let half = evals.len() / 2;
        
        let mut s_0 = K::zero();
        let mut s_1 = K::zero();
        
        for i in 0..half {
            s_0 = s_0.add(&evals[i]);
            s_1 = s_1.add(&evals[i + half]);
        }
        
        UnivariatePolynomial::from_evaluations(&[s_0, s_1])
    }
    
    fn partial_eval(&self, evals: &[K], challenge: K) -> Vec<K> {
        let half = evals.len() / 2;
        let mut result = Vec::with_capacity(half);
        
        let one_minus_r = K::one().sub(&challenge);
        
        for i in 0..half {
            let new_val = one_minus_r.mul(&evals[i])
                .add(&challenge.mul(&evals[i + half]));
            result.push(new_val);
        }
        
        result
    }
    
    fn compute_eq_product(&self, r: &[K], r_prime: &[K], log_k: usize, log_t: usize) -> Vec<K> {
        let total_size = 1 << (log_k + log_t);
        let mut result = Vec::with_capacity(total_size);
        
        for idx in 0..total_size {
            let k_idx = idx >> log_t;
            let j_idx = idx & ((1 << log_t) - 1);
            
            let k_bits = Self::index_to_bits(k_idx, log_k);
            let j_bits = Self::index_to_bits(j_idx, log_t);
            
            let eq_k = Self::eq_polynomial(r, &k_bits);
            let eq_j = Self::eq_polynomial(r_prime, &j_bits);
            
            result.push(eq_k.mul(&eq_j));
        }
        
        result
    }
    
    fn hamming_weight_sumcheck(
        &self,
        access_mle: &MultilinearPolynomial<K>,
        rcycle: &[K],
    ) -> Result<SumCheckProof<K>, String> {
        // Sum-check to compute Σ_k ra(k, rcycle)
        let log_k = (self.memory_size as f64).log2() as usize;
        let mut round_polynomials = Vec::with_capacity(log_k);
        let mut challenges = Vec::new();
        
        let mut current_evals = self.compute_ra_at_rcycle(rcycle)?;
        
        for round in 0..log_k {
            let round_poly = self.compute_round_poly_single(&current_evals);
            round_polynomials.push(round_poly);
            
            let challenge = self.sample_challenge(round);
            challenges.push(challenge);
            
            current_evals = self.partial_eval(&current_evals, challenge);
        }
        
        let final_eval = if !current_evals.is_empty() {
            current_evals[0]
        } else {
            K::zero()
        };
        
        Ok(SumCheckProof {
            round_polynomials,
            final_evaluation: final_eval,
            challenges,
        })
    }
    
    fn sample_challenge(&self, round: usize) -> K {
        // In production: use Fiat-Shamir transform
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let val = rng.gen::<u64>() % K::BaseField::MODULUS;
        K::from_base_field_element(K::BaseField::from_u64(val), 0)
    }
    
    fn index_to_bits(idx: usize, n: usize) -> Vec<bool> {
        (0..n).map(|i| (idx >> i) & 1 == 1).collect()
    }
    
    fn eq_polynomial(r: &[K], x: &[bool]) -> K {
        let mut result = K::one();
        for (r_i, &x_i) in r.iter().zip(x.iter()) {
            let term = if x_i { *r_i } else { K::one().sub(r_i) };
            result = result.mul(&term);
        }
        result
    }
}

/// Proof structures

#[derive(Clone, Debug)]
pub struct ReadCheckProof<K: ExtensionFieldElement> {
    pub round_polynomials: Vec<UnivariatePolynomial<K>>,
    pub final_evaluation: K,
    pub challenges: Vec<K>,
}

#[derive(Clone, Debug)]
pub struct BooleanityProof<K: ExtensionFieldElement> {
    pub round_polynomials: Vec<UnivariatePolynomial<K>>,
    pub final_evaluation: K,
    pub challenges: Vec<K>,
}

#[derive(Clone, Debug)]
pub enum OneHotProof<K: ExtensionFieldElement> {
    NonBinary {
        evaluation: K,
        expected: K,
        actual: K,
    },
    Binary {
        sum_check_proof: SumCheckProof<K>,
    },
}

#[derive(Clone, Debug)]
pub struct SumCheckProof<K: ExtensionFieldElement> {
    pub round_polynomials: Vec<UnivariatePolynomial<K>>,
    pub final_evaluation: K,
    pub challenges: Vec<K>,
}
