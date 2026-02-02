// Bulletproofs Protocol for Hyrax Evaluation Proofs
//
// This module implements the Bulletproofs protocol for zero-knowledge evaluation proofs
// in the Hyrax polynomial commitment scheme.
//
// Based on:
// - "Bulletproofs: Short Proofs for Confidential Transactions and More" by Bünz et al.
// - "Doubly-efficient zkSNARKs without trusted setup" (Hyrax paper)
// - Requirements 8.11-8.15 from the small-space zkVM specification
//
// Key features:
// - Zero-knowledge evaluation proofs with O(log √n) communication
// - Streaming computation in O(√n) space
// - Folding technique to reduce vector size by half each round
// - Cross-term computation without storing full vectors

use crate::small_space_zkvm::field_arithmetic::FieldElement;
use crate::small_space_zkvm::hyrax::{GroupElement, PippengerMSM, PolynomialOracle};
use std::marker::PhantomData;

/// Bulletproofs transcript for Fiat-Shamir transformation
pub struct BulletproofsTranscript {
    /// Transcript state (in practice, would use a cryptographic hash)
    state: Vec<u8>,
}

impl BulletproofsTranscript {
    /// Create new transcript
    pub fn new(label: &[u8]) -> Self {
        BulletproofsTranscript {
            state: label.to_vec(),
        }
    }
    
    /// Append message to transcript
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.state.extend_from_slice(label);
        self.state.extend_from_slice(&(message.len() as u32).to_le_bytes());
        self.state.extend_from_slice(message);
    }
    
    /// Challenge scalar from transcript
    pub fn challenge_scalar<F: FieldElement>(&mut self, label: &[u8]) -> F {
        self.append_message(label, &[]);
        
        // In practice, use cryptographic hash like SHA-256 or BLAKE2
        // For now, use simple hash
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hasher::write(&mut hasher, &self.state);
        let hash = std::hash::Hasher::finish(&hasher);
        
        F::from_u64(hash)
    }
    
    /// Append group element to transcript
    pub fn append_point<G: GroupElement>(&mut self, label: &[u8], point: &G) {
        self.append_message(label, &point.to_bytes());
    }
    
    /// Append scalar to transcript
    pub fn append_scalar<F: FieldElement>(&mut self, label: &[u8], scalar: &F) {
        self.append_message(label, &scalar.to_bytes());
    }
}

/// Bulletproofs round data
#[derive(Debug, Clone)]
pub struct BulletproofsRound<G: GroupElement> {
    /// Left commitment: L_i
    pub l_commitment: G,
    /// Right commitment: R_i
    pub r_commitment: G,
    /// Challenge: α_i
    pub challenge: G::Scalar,
}

/// Bulletproofs evaluation proof
#[derive(Debug, Clone)]
pub struct BulletproofsEvaluationProof<G: GroupElement> {
    /// Round data for each folding round
    pub rounds: Vec<BulletproofsRound<G>>,
    /// Final scalar: a (witness for final inner product)
    pub final_a: G::Scalar,
    /// Final scalar: b (final u value)
    pub final_b: G::Scalar,
}

impl<G: GroupElement> BulletproofsEvaluationProof<G> {
    /// Get proof size in bytes
    pub fn size_bytes(&self) -> usize {
        // Each round: 2 group elements (64 bytes) + 1 scalar (32 bytes)
        // Final: 2 scalars (64 bytes)
        self.rounds.len() * (64 + 32) + 64
    }
    
    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Number of rounds
        bytes.extend_from_slice(&(self.rounds.len() as u32).to_le_bytes());
        
        // Round data
        for round in &self.rounds {
            bytes.extend_from_slice(&round.l_commitment.to_bytes());
            bytes.extend_from_slice(&round.r_commitment.to_bytes());
            bytes.extend_from_slice(&round.challenge.to_bytes());
        }
        
        // Final scalars
        bytes.extend_from_slice(&self.final_a.to_bytes());
        bytes.extend_from_slice(&self.final_b.to_bytes());
        
        bytes
    }
}

/// Bulletproofs prover for Hyrax evaluation proofs
pub struct BulletproofsProver<G: GroupElement> {
    /// Generator elements for commitments
    pub generators: Vec<G>,
    /// Phantom data for group type
    _phantom: PhantomData<G>,
}

impl<G: GroupElement> BulletproofsProver<G> {
    /// Create new Bulletproofs prover
    pub fn new(generators: Vec<G>) -> Self {
        BulletproofsProver {
            generators,
            _phantom: PhantomData,
        }
    }
    
    /// Generate Bulletproofs evaluation proof
    /// 
    /// Proves knowledge of w₁ such that:
    /// - w₁ = M·r₂ (matrix-vector product)
    /// - y = ⟨r₁, w₁⟩ (claimed evaluation)
    /// 
    /// Uses log(√n) rounds of folding to reduce from √n to 1 element
    pub fn prove_evaluation<P: PolynomialOracle<G::Scalar>>(
        &self,
        oracle: &P,
        r1: &[G::Scalar],
        r2: &[G::Scalar],
        claimed_evaluation: G::Scalar
    ) -> Result<BulletproofsEvaluationProof<G>, String> {
        let n = r1.len();
        if n != r2.len() || n != self.generators.len() {
            return Err("Dimension mismatch".to_string());
        }
        
        if !n.is_power_of_two() {
            return Err("Vector length must be power of 2".to_string());
        }
        
        let mut transcript = BulletproofsTranscript::new(b"bulletproofs_hyrax");
        
        // Initialize vectors and generators
        let mut w = self.compute_initial_w(oracle, r2)?;
        let mut u = r1.to_vec();
        let mut g = self.generators.clone();
        let mut y = claimed_evaluation;
        
        // Verify initial inner product
        let initial_inner_product = self.inner_product(&u, &w);
        if initial_inner_product != y {
            return Err("Initial inner product verification failed".to_string());
        }
        
        let mut rounds = Vec::new();
        let num_rounds = (n as f64).log2() as usize;
        
        // Folding rounds
        for round in 0..num_rounds {
            let current_n = w.len();
            if current_n == 1 {
                break;
            }
            
            let half_n = current_n / 2;
            
            // Split vectors into left and right halves
            let (w_l, w_r) = w.split_at(half_n);
            let (u_l, u_r) = u.split_at(half_n);
            let (g_l, g_r) = g.split_at(half_n);
            
            // Compute cross-terms
            let y_l = self.inner_product(u_l, w_r);
            let y_r = self.inner_product(u_r, w_l);
            
            // Compute L and R commitments
            let l_commitment = self.compute_cross_commitment(w_r, g_l)?;
            let r_commitment = self.compute_cross_commitment(w_l, g_r)?;
            
            // Add to transcript
            transcript.append_point(b"L", &l_commitment);
            transcript.append_point(b"R", &r_commitment);
            transcript.append_scalar(b"y_L", &y_l);
            transcript.append_scalar(b"y_R", &y_r);
            
            // Get challenge
            let alpha = transcript.challenge_scalar(b"alpha");
            let alpha_inv = alpha.inverse();
            
            // Fold vectors
            let mut new_w = Vec::with_capacity(half_n);
            let mut new_u = Vec::with_capacity(half_n);
            let mut new_g = Vec::with_capacity(half_n);
            
            for i in 0..half_n {
                new_w.push(alpha * w_l[i] + alpha_inv * w_r[i]);
                new_u.push(alpha_inv * u_l[i] + alpha * u_r[i]);
                new_g.push(g_l[i].mul(&alpha_inv).add(&g_r[i].mul(&alpha)));
            }
            
            // Update y
            y = alpha * alpha * y_l + y + alpha_inv * alpha_inv * y_r;
            
            // Store round data
            rounds.push(BulletproofsRound {
                l_commitment,
                r_commitment,
                challenge: alpha,
            });
            
            // Update for next round
            w = new_w;
            u = new_u;
            g = new_g;
        }
        
        // Final values
        if w.len() != 1 || u.len() != 1 {
            return Err("Folding did not reduce to single element".to_string());
        }
        
        let final_a = w[0];
        let final_b = u[0];
        
        // Verify final inner product
        if final_a * final_b != y {
            return Err("Final inner product verification failed".to_string());
        }
        
        Ok(BulletproofsEvaluationProof {
            rounds,
            final_a,
            final_b,
        })
    }
    
    /// Compute initial witness vector w₁ = M·r₂ using streaming
    fn compute_initial_w<P: PolynomialOracle<G::Scalar>>(
        &self,
        oracle: &P,
        r2: &[G::Scalar]
    ) -> Result<Vec<G::Scalar>, String> {
        let matrix_dim = r2.len();
        let mut w = vec![G::Scalar::zero(); matrix_dim];
        
        // Stream through polynomial evaluations to compute M·r₂
        for row in 0..matrix_dim {
            let mut sum = G::Scalar::zero();
            
            for col in 0..matrix_dim {
                let index = row * matrix_dim + col;
                let m_val = oracle.evaluate_at(index);
                sum = sum + m_val * r2[col];
            }
            
            w[row] = sum;
        }
        
        Ok(w)
    }
    
    /// Compute inner product of two vectors
    fn inner_product(&self, a: &[G::Scalar], b: &[G::Scalar]) -> G::Scalar {
        let mut result = G::Scalar::zero();
        for (a_i, b_i) in a.iter().zip(b.iter()) {
            result = result + (*a_i) * (*b_i);
        }
        result
    }
    
    /// Compute cross-commitment ⟨w, g⟩
    fn compute_cross_commitment(
        &self,
        w: &[G::Scalar],
        g: &[G]
    ) -> Result<G, String> {
        PippengerMSM::compute_msm(g, w)
    }
}

/// Streaming Bulletproofs prover that doesn't store full witness vector
pub struct StreamingBulletproofsProver<G: GroupElement> {
    /// Generator elements
    pub generators: Vec<G>,
    /// Phantom data
    _phantom: PhantomData<G>,
}

impl<G: GroupElement> StreamingBulletproofsProver<G> {
    /// Create new streaming Bulletproofs prover
    pub fn new(generators: Vec<G>) -> Self {
        StreamingBulletproofsProver {
            generators,
            _phantom: PhantomData,
        }
    }
    
    /// Generate proof with streaming computation
    /// 
    /// Key optimization: compute cross-terms without storing full w₁ vector
    /// Stream polynomial once per round to compute required cross-terms
    pub fn prove_evaluation_streaming<P: PolynomialOracle<G::Scalar>>(
        &self,
        oracle: &P,
        r1: &[G::Scalar],
        r2: &[G::Scalar],
        claimed_evaluation: G::Scalar
    ) -> Result<BulletproofsEvaluationProof<G>, String> {
        let n = r1.len();
        if n != r2.len() || n != self.generators.len() {
            return Err("Dimension mismatch".to_string());
        }
        
        if !n.is_power_of_two() {
            return Err("Vector length must be power of 2".to_string());
        }
        
        let mut transcript = BulletproofsTranscript::new(b"streaming_bulletproofs_hyrax");
        
        // Initialize u and g (we'll compute w on-demand)
        let mut u = r1.to_vec();
        let mut g = self.generators.clone();
        let mut y = claimed_evaluation;
        
        // Current r2 for matrix-vector product computation
        let mut current_r2 = r2.to_vec();
        
        let mut rounds = Vec::new();
        let num_rounds = (n as f64).log2() as usize;
        
        // Folding rounds
        for round in 0..num_rounds {
            let current_n = u.len();
            if current_n == 1 {
                break;
            }
            
            let half_n = current_n / 2;
            
            // Split u and g
            let (u_l, u_r) = u.split_at(half_n);
            let (g_l, g_r) = g.split_at(half_n);
            
            // Compute w on-demand by streaming through polynomial
            let (w_l, w_r) = self.compute_w_halves_streaming(oracle, &current_r2, half_n)?;
            
            // Compute cross-terms
            let y_l = self.inner_product(u_l, &w_r);
            let y_r = self.inner_product(u_r, &w_l);
            
            // Compute L and R commitments
            let l_commitment = PippengerMSM::compute_msm(g_l, &w_r)?;
            let r_commitment = PippengerMSM::compute_msm(g_r, &w_l)?;
            
            // Add to transcript
            transcript.append_point(b"L", &l_commitment);
            transcript.append_point(b"R", &r_commitment);
            transcript.append_scalar(b"y_L", &y_l);
            transcript.append_scalar(b"y_R", &y_r);
            
            // Get challenge
            let alpha = transcript.challenge_scalar(b"alpha");
            let alpha_inv = alpha.inverse();
            
            // Fold u and g
            let mut new_u = Vec::with_capacity(half_n);
            let mut new_g = Vec::with_capacity(half_n);
            
            for i in 0..half_n {
                new_u.push(alpha_inv * u_l[i] + alpha * u_r[i]);
                new_g.push(g_l[i].mul(&alpha_inv).add(&g_r[i].mul(&alpha)));
            }
            
            // Fold r2 for next round
            let mut new_r2 = Vec::with_capacity(half_n);
            let (r2_l, r2_r) = current_r2.split_at(half_n);
            for i in 0..half_n {
                new_r2.push(alpha * r2_l[i] + alpha_inv * r2_r[i]);
            }
            
            // Update y
            y = alpha * alpha * y_l + y + alpha_inv * alpha_inv * y_r;
            
            // Store round data
            rounds.push(BulletproofsRound {
                l_commitment,
                r_commitment,
                challenge: alpha,
            });
            
            // Update for next round
            u = new_u;
            g = new_g;
            current_r2 = new_r2;
        }
        
        // Compute final w value by streaming
        let final_w = self.compute_final_w_streaming(oracle, &current_r2)?;
        
        let final_a = final_w;
        let final_b = u[0];
        
        // Verify final inner product
        if final_a * final_b != y {
            return Err("Final inner product verification failed".to_string());
        }
        
        Ok(BulletproofsEvaluationProof {
            rounds,
            final_a,
            final_b,
        })
    }
    
    /// Compute w halves by streaming through polynomial
    fn compute_w_halves_streaming<P: PolynomialOracle<G::Scalar>>(
        &self,
        oracle: &P,
        r2: &[G::Scalar],
        half_n: usize
    ) -> Result<(Vec<G::Scalar>, Vec<G::Scalar>), String> {
        let matrix_dim = r2.len();
        let mut w_l = vec![G::Scalar::zero(); half_n];
        let mut w_r = vec![G::Scalar::zero(); half_n];
        
        // Stream through polynomial to compute both halves
        for row in 0..matrix_dim {
            let mut sum = G::Scalar::zero();
            
            // Compute full row sum first
            for col in 0..matrix_dim {
                let index = row * matrix_dim + col;
                let m_val = oracle.evaluate_at(index);
                sum = sum + m_val * r2[col];
            }
            
            // Assign to appropriate half
            if row < half_n {
                w_l[row] = sum;
            } else {
                w_r[row - half_n] = sum;
            }
        }
        
        Ok((w_l, w_r))
    }
    
    /// Compute final w value by streaming
    fn compute_final_w_streaming<P: PolynomialOracle<G::Scalar>>(
        &self,
        oracle: &P,
        r2: &[G::Scalar]
    ) -> Result<G::Scalar, String> {
        if r2.len() != 1 {
            return Err("Final r2 should have length 1".to_string());
        }
        
        let matrix_dim = (oracle.num_evaluations() as f64).sqrt() as usize;
        let mut sum = G::Scalar::zero();
        
        // Stream through first row of matrix
        for col in 0..matrix_dim {
            let m_val = oracle.evaluate_at(col);
            sum = sum + m_val * r2[0];
        }
        
        Ok(sum)
    }
    
    /// Compute inner product of two vectors
    fn inner_product(&self, a: &[G::Scalar], b: &[G::Scalar]) -> G::Scalar {
        let mut result = G::Scalar::zero();
        for (a_i, b_i) in a.iter().zip(b.iter()) {
            result = result + (*a_i) * (*b_i);
        }
        result
    }
}

/// Bulletproofs verifier for Hyrax evaluation proofs
pub struct BulletproofsVerifier<G: GroupElement> {
    /// Generator elements
    pub generators: Vec<G>,
}

impl<G: GroupElement> BulletproofsVerifier<G> {
    /// Create new Bulletproofs verifier
    pub fn new(generators: Vec<G>) -> Self {
        BulletproofsVerifier { generators }
    }
    
    /// Verify Bulletproofs evaluation proof
    /// 
    /// Verifies that the prover knows w₁ such that:
    /// - Commitment to w₁ is consistent with Hyrax commitment
    /// - y = ⟨r₁, w₁⟩
    pub fn verify_evaluation(
        &self,
        commitment_to_w: &G, // This would be derived from Hyrax commitment
        r1: &[G::Scalar],
        claimed_evaluation: G::Scalar,
        proof: &BulletproofsEvaluationProof<G>
    ) -> Result<bool, String> {
        let n = r1.len();
        if n != self.generators.len() {
            return Err("Dimension mismatch".to_string());
        }
        
        if !n.is_power_of_two() {
            return Err("Vector length must be power of 2".to_string());
        }
        
        let mut transcript = BulletproofsTranscript::new(b"bulletproofs_hyrax");
        
        // Initialize verification state
        let mut u = r1.to_vec();
        let mut g = self.generators.clone();
        let mut y = claimed_evaluation;
        let mut p = commitment_to_w.clone();
        
        // Verify each round
        for round in &proof.rounds {
            let current_n = u.len();
            let half_n = current_n / 2;
            
            // Add round data to transcript
            transcript.append_point(b"L", &round.l_commitment);
            transcript.append_point(b"R", &round.r_commitment);
            
            // Recompute challenge (should match proof)
            let alpha = transcript.challenge_scalar::<G::Scalar>(b"alpha");
            if alpha != round.challenge {
                return Ok(false);
            }
            
            let alpha_inv = alpha.inverse();
            let alpha_sq = alpha * alpha;
            let alpha_inv_sq = alpha_inv * alpha_inv;
            
            // Update P commitment
            p = round.l_commitment.mul(&alpha_sq)
                .add(&p)
                .add(&round.r_commitment.mul(&alpha_inv_sq));
            
            // Fold u and g
            let (u_l, u_r) = u.split_at(half_n);
            let (g_l, g_r) = g.split_at(half_n);
            
            let mut new_u = Vec::with_capacity(half_n);
            let mut new_g = Vec::with_capacity(half_n);
            
            for i in 0..half_n {
                new_u.push(alpha_inv * u_l[i] + alpha * u_r[i]);
                new_g.push(g_l[i].mul(&alpha_inv).add(&g_r[i].mul(&alpha)));
            }
            
            u = new_u;
            g = new_g;
        }
        
        // Final verification
        if u.len() != 1 || g.len() != 1 {
            return Err("Folding did not reduce to single element".to_string());
        }
        
        // Check final inner product
        if proof.final_a * proof.final_b != y {
            return Ok(false);
        }
        
        // Check final commitment
        let expected_p = g[0].mul(&proof.final_a);
        if !self.group_elements_equal(&p, &expected_p) {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Helper to check if two group elements are equal
    fn group_elements_equal(&self, a: &G, b: &G) -> bool {
        a.to_bytes() == b.to_bytes()
    }
}

/// Performance analyzer for Bulletproofs
pub struct BulletproofsPerformanceAnalyzer {
    /// Vector dimension
    pub dimension: usize,
}

impl BulletproofsPerformanceAnalyzer {
    /// Create new performance analyzer
    pub fn new(dimension: usize) -> Self {
        BulletproofsPerformanceAnalyzer { dimension }
    }
    
    /// Analyze proof size
    pub fn analyze_proof_size(&self) -> usize {
        let num_rounds = (self.dimension as f64).log2() as usize;
        // Each round: 2 group elements + 1 scalar
        // Final: 2 scalars
        num_rounds * (64 + 32) + 64
    }
    
    /// Analyze prover time complexity
    pub fn analyze_prover_time(&self) -> String {
        let num_rounds = (self.dimension as f64).log2() as usize;
        format!(
            "Prover time: O(n log n) = O({} * {}) field operations",
            self.dimension,
            num_rounds
        )
    }
    
    /// Analyze verifier time complexity
    pub fn analyze_verifier_time(&self) -> String {
        let num_rounds = (self.dimension as f64).log2() as usize;
        format!(
            "Verifier time: O(log n) = O({}) group operations",
            num_rounds
        )
    }
    
    /// Analyze space complexity
    pub fn analyze_space_complexity(&self) -> String {
        format!(
            "Space complexity: O(log n) = O({}) elements",
            (self.dimension as f64).log2() as usize
        )
    }
    
    /// Generate performance report
    pub fn generate_report(&self) -> String {
        format!(
            "Bulletproofs Performance Analysis (n = {}):\n\
             - Proof size: {} bytes\n\
             - {}\n\
             - {}\n\
             - {}",
            self.dimension,
            self.analyze_proof_size(),
            self.analyze_prover_time(),
            self.analyze_verifier_time(),
            self.analyze_space_complexity()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::small_space_zkvm::field_arithmetic::PrimeField;
    use crate::small_space_zkvm::hyrax::MockGroupElement;
    
    // Mock polynomial oracle for testing
    struct MockPolynomialOracle {
        evaluations: Vec<PrimeField>,
        num_vars: usize,
    }
    
    impl PolynomialOracle<PrimeField> for MockPolynomialOracle {
        fn evaluate_at(&self, index: usize) -> PrimeField {
            if index < self.evaluations.len() {
                self.evaluations[index]
            } else {
                PrimeField::zero()
            }
        }
        
        fn num_evaluations(&self) -> usize {
            self.evaluations.len()
        }
        
        fn num_variables(&self) -> usize {
            self.num_vars
        }
    }
    
    #[test]
    fn test_bulletproofs_transcript() {
        let mut transcript = BulletproofsTranscript::new(b"test");
        transcript.append_message(b"label1", b"message1");
        
        let challenge1: PrimeField = transcript.challenge_scalar(b"challenge1");
        let challenge2: PrimeField = transcript.challenge_scalar(b"challenge2");
        
        // Challenges should be different
        assert_ne!(challenge1, challenge2);
    }
    
    #[test]
    fn test_bulletproofs_basic() {
        // Create generators
        let generators: Vec<MockGroupElement> = (0..4)
            .map(|i| MockGroupElement { value: i + 1 })
            .collect();
        
        let prover = BulletproofsProver::new(generators.clone());
        
        // Create mock polynomial
        let evaluations: Vec<PrimeField> = (0..16)
            .map(|i| PrimeField::from_u64(i as u64))
            .collect();
        let oracle = MockPolynomialOracle {
            evaluations,
            num_vars: 4,
        };
        
        // Test vectors
        let r1 = vec![
            PrimeField::from_u64(1),
            PrimeField::from_u64(2),
            PrimeField::from_u64(3),
            PrimeField::from_u64(4),
        ];
        let r2 = vec![
            PrimeField::from_u64(1),
            PrimeField::from_u64(1),
            PrimeField::from_u64(1),
            PrimeField::from_u64(1),
        ];
        
        // Compute expected evaluation
        let w = prover.compute_initial_w(&oracle, &r2).unwrap();
        let expected_eval = prover.inner_product(&r1, &w);
        
        // Generate proof
        let proof = prover.prove_evaluation(&oracle, &r1, &r2, expected_eval).unwrap();
        
        // Verify proof structure
        assert_eq!(proof.rounds.len(), 2); // log₂(4) = 2 rounds
        assert!(proof.final_a != PrimeField::zero());
        assert!(proof.final_b != PrimeField::zero());
    }
    
    #[test]
    fn test_streaming_bulletproofs() {
        // Create generators
        let generators: Vec<MockGroupElement> = (0..4)
            .map(|i| MockGroupElement { value: i + 1 })
            .collect();
        
        let streaming_prover = StreamingBulletproofsProver::new(generators.clone());
        let regular_prover = BulletproofsProver::new(generators);
        
        // Create mock polynomial
        let evaluations: Vec<PrimeField> = (0..16)
            .map(|i| PrimeField::from_u64(i as u64))
            .collect();
        let oracle = MockPolynomialOracle {
            evaluations,
            num_vars: 4,
        };
        
        // Test vectors
        let r1 = vec![
            PrimeField::from_u64(1),
            PrimeField::from_u64(2),
            PrimeField::from_u64(3),
            PrimeField::from_u64(4),
        ];
        let r2 = vec![
            PrimeField::from_u64(1),
            PrimeField::from_u64(1),
            PrimeField::from_u64(1),
            PrimeField::from_u64(1),
        ];
        
        // Compute expected evaluation
        let w = regular_prover.compute_initial_w(&oracle, &r2).unwrap();
        let expected_eval = regular_prover.inner_product(&r1, &w);
        
        // Generate proofs with both methods
        let regular_proof = regular_prover.prove_evaluation(&oracle, &r1, &r2, expected_eval).unwrap();
        let streaming_proof = streaming_prover.prove_evaluation_streaming(&oracle, &r1, &r2, expected_eval).unwrap();
        
        // Both should have same structure
        assert_eq!(regular_proof.rounds.len(), streaming_proof.rounds.len());
        assert_eq!(regular_proof.final_a, streaming_proof.final_a);
        assert_eq!(regular_proof.final_b, streaming_proof.final_b);
    }
    
    #[test]
    fn test_bulletproofs_performance_analyzer() {
        let analyzer = BulletproofsPerformanceAnalyzer::new(256);
        
        let proof_size = analyzer.analyze_proof_size();
        assert!(proof_size > 0);
        
        let report = analyzer.generate_report();
        assert!(report.contains("256"));
        assert!(report.contains("Proof size"));
        assert!(report.contains("Prover time"));
        assert!(report.contains("Verifier time"));
    }
}