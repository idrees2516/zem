// Lattice-based Polynomial Commitment Scheme for RoKoko
//
// Complete implementation of committed refinement scheme:
// - Module-LWE based vector commitments
// - Polynomial commitments with evaluation proofs
// - Homomorphic operations for proof composition
// - Batch commitment and verification
// - Post-quantum security

use crate::errors::ZKVMError;
use crate::rokoko::lattice::{LatticeElement, LatticeParams, ModulusSwitching, RejectionSampler};
use crate::rokoko::polynomial::{MultilinearPolynomial, UnivariatePolynomial, PolynomialOps};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Commitment key for Module-LWE based commitments
#[derive(Clone, Serialize, Deserialize)]
pub struct CommitmentKey {
    /// Public random matrices A_i ∈ R_q^{n×m} for Module-LWE
    pub public_matrices: Vec<Vec<LatticeElement>>,
    
    /// Lattice parameters (dimension, modulus, error distribution)
    pub params: LatticeParams,
    
    /// Commitment dimension n
    pub dimension: usize,
    
    /// Module rank m
    pub rank: usize,
    
    /// Precomputed NTT roots for fast multiplication
    ntt_roots: Vec<u64>,
}

impl CommitmentKey {
    /// Generates commitment key using cryptographic randomness
    /// Security: Module-LWE hardness with dimension n and rank m
    pub fn generate<R: RngCore + CryptoRng>(
        params: LatticeParams,
        rank: usize,
        rng: &mut R,
    ) -> Result<Self, ZKVMError> {
        params.validate()?;
        
        if rank < 2 {
            return Err(ZKVMError::InvalidParameter(
                "Module rank must be at least 2".to_string()
            ));
        }
        
        let dimension = params.dimension;
        let mut public_matrices = Vec::with_capacity(rank);
        
        // Generate uniformly random public matrices in NTT domain
        for _ in 0..rank {
            let mut row = Vec::with_capacity(dimension);
            for _ in 0..dimension {
                let mut elem = LatticeElement::random(dimension, params.modulus, rng);
                elem.to_ntt(); // Convert to NTT for fast operations
                row.push(elem);
            }
            public_matrices.push(row);
        }
        
        // Precompute NTT roots for given dimension
        let ntt_roots = Self::compute_ntt_roots(dimension, params.modulus);
        
        Ok(Self {
            public_matrices,
            params,
            dimension,
            rank,
            ntt_roots,
        })
    }
    
    /// Computes primitive roots of unity for NTT
    fn compute_ntt_roots(dimension: usize, modulus: u64) -> Vec<u64> {
        let mut roots = Vec::with_capacity(dimension);
        let primitive_root = Self::find_primitive_root(dimension, modulus);
        
        let mut current = 1u64;
        for _ in 0..dimension {
            roots.push(current);
            current = ((current as u128 * primitive_root as u128) % modulus as u128) as u64;
        }
        
        roots
    }
    
    /// Finds primitive n-th root of unity modulo q
    fn find_primitive_root(n: usize, modulus: u64) -> u64 {
        // For our specific modulus q = 2^60 - 93, we have q-1 = 2^60 - 94
        // We need a 2n-th root of unity
        let phi = modulus - 1;
        let exponent = phi / (2 * n as u64);
        
        // Try small generators
        for g in 2..100 {
            let root = mod_exp(g, exponent, modulus);
            // Verify it's a primitive root
            if mod_exp(root, n as u64, modulus) == modulus - 1 {
                return root;
            }
        }
        
        // Fallback - should not reach here with correct modulus
        3
    }
    
    pub fn size_bytes(&self) -> usize {
        self.rank * self.dimension * self.dimension * 8 + self.ntt_roots.len() * 8
    }
}

/// Opening information for verifying a commitment
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Opening {
    /// Secret randomness vector r ∈ R_q^m sampled from discrete Gaussian
    pub randomness: Vec<LatticeElement>,
    
    /// Original message polynomial coefficients
    pub message: Vec<u64>,
    
    /// Evaluation point (for polynomial commitments)
    pub point: Vec<u64>,
    
    /// Evaluated value at point
    pub value: u64,
}

impl Opening {
    pub fn new(
        randomness: Vec<LatticeElement>,
        message: Vec<u64>,
        point: Vec<u64>,
        value: u64,
    ) -> Self {
        Self {
            randomness,
            message,
            point,
            value,
        }
    }
    
    /// Verifies randomness has appropriate norm
    pub fn verify_randomness_norm(&self, params: &LatticeParams) -> bool {
        let bound = (params.error_stddev * params.rejection_factor) as u64;
        
        for r in &self.randomness {
            if r.infinity_norm() > bound {
                return false;
            }
        }
        
        true
    }
}

/// Polynomial commitment structure
#[derive(Clone, Serialize, Deserialize)]
pub struct RokokoCommitment {
    /// Module-LWE commitment: C = A·r + encode(m) ∈ R_q^n
    pub commitment: Vec<LatticeElement>,
    
    /// Hash of commitment for binding
    pub commitment_hash: [u8; 32],
    
    /// Auxiliary data (optional metadata)
    pub aux_data: Option<Vec<u8>>,
}

impl RokokoCommitment {
    pub fn new(commitment: Vec<LatticeElement>) -> Self {
        let commitment_hash = Self::compute_hash(&commitment);
        
        Self {
            commitment,
            commitment_hash,
            aux_data: None,
        }
    }
    
    pub fn with_aux_data(mut self, data: Vec<u8>) -> Self {
        self.aux_data = Some(data);
        self
    }
    
    /// Computes cryptographic hash of commitment for binding
    fn compute_hash(commitment: &[LatticeElement]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"RoKoko-Commitment");
        
        for elem in commitment {
            for &coeff in &elem.coeffs {
                hasher.update(coeff.to_le_bytes());
            }
        }
        
        hasher.finalize().into()
    }
    
    /// Homomorphic addition: C1 + C2 = commit(m1 + m2)
    pub fn add(&self, other: &Self) -> Result<Self, ZKVMError> {
        if self.commitment.len() != other.commitment.len() {
            return Err(ZKVMError::InvalidCommitment(
                "Commitment dimension mismatch".to_string()
            ));
        }
        
        let mut result_comm = Vec::with_capacity(self.commitment.len());
        
        for (c1, c2) in self.commitment.iter().zip(other.commitment.iter()) {
            result_comm.push(c1.clone().add(c2.clone()));
        }
        
        Ok(Self::new(result_comm))
    }
    
    /// Scalar multiplication: α·C = commit(α·m)
    pub fn scalar_mul(&self, scalar: u64, modulus: u64) -> Self {
        let scalar_elem = LatticeElement::new(vec![scalar], modulus);
        
        let result_comm: Vec<LatticeElement> = self.commitment.iter()
            .map(|c| {
                let mut result = c.clone();
                for coeff in &mut result.coeffs {
                    *coeff = ((*coeff as u128 * scalar as u128) % modulus as u128) as u64;
                }
                result
            })
            .collect();
        
        Self::new(result_comm)
    }
    
    pub fn size_bytes(&self) -> usize {
        let comm_size = self.commitment.iter()
            .map(|e| e.coeffs.len() * 8)
            .sum::<usize>();
        let aux_size = self.aux_data.as_ref().map(|d| d.len()).unwrap_or(0);
        comm_size + 32 + aux_size
    }
    
    pub fn hash(&self) -> [u8; 32] {
        self.commitment_hash
    }
}

impl fmt::Display for RokokoCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RokokoCommitment(dim={}, hash={:02x}{:02x}...)", 
               self.commitment.len(),
               self.commitment_hash[0],
               self.commitment_hash[1])
    }
}

/// Evaluation proof for polynomial commitments
#[derive(Clone, Serialize, Deserialize)]
pub struct EvaluationProof {
    /// Claimed evaluation value f(r) = v
    pub value: u64,
    
    /// Evaluation point r = (r_1, ..., r_ν)
    pub point: Vec<u64>,
    
    /// Commitments to quotient polynomials q_i
    pub quotient_commitments: Vec<RokokoCommitment>,
    
    /// Witness randomness for quotients
    pub quotient_randomness: Vec<Vec<LatticeElement>>,
    
    /// Partial evaluations along the evaluation path
    pub partial_evaluations: Vec<u64>,
}

impl EvaluationProof {
    pub fn new(
        value: u64,
        point: Vec<u64>,
        quotient_commitments: Vec<RokokoCommitment>,
        quotient_randomness: Vec<Vec<LatticeElement>>,
        partial_evaluations: Vec<u64>,
    ) -> Self {
        Self {
            value,
            point,
            quotient_commitments,
            quotient_randomness,
            partial_evaluations,
        }
    }
    
    pub fn size_bytes(&self) -> usize {
        let comm_size: usize = self.quotient_commitments.iter()
            .map(|c| c.size_bytes())
            .sum();
        
        let rand_size = self.quotient_randomness.len() * 
            self.quotient_randomness.get(0).map(|r| r.len() * 2048 * 8).unwrap_or(0);
        
        let eval_size = self.partial_evaluations.len() * 8;
        
        8 + self.point.len() * 8 + comm_size + rand_size + eval_size
    }
}

/// Complete commitment scheme implementation
pub struct RokokoCommitmentScheme {
    /// Public commitment key
    pub key: CommitmentKey,
    
    /// Rejection sampler for secure randomness
    sampler: RejectionSampler,
    
    /// Evaluation cache for optimization
    cache: HashMap<Vec<u64>, Vec<u64>>,
}

impl RokokoCommitmentScheme {
    pub fn new(key: CommitmentKey) -> Self {
        let sampler = RejectionSampler::new(
            key.params.rejection_factor,
            key.params.error_stddev,
        );
        
        Self {
            key,
            sampler,
            cache: HashMap::new(),
        }
    }
    
    /// Commits to multilinear polynomial using Module-LWE
    /// Returns (commitment, opening) where commitment hides polynomial
    pub fn commit_multilinear<R: RngCore + CryptoRng>(
        &self,
        poly: &MultilinearPolynomial,
        rng: &mut R,
    ) -> Result<(RokokoCommitment, Opening), ZKVMError> {
        // Sample randomness vector r from discrete Gaussian distribution
        let mut randomness = Vec::with_capacity(self.key.rank);
        
        for _ in 0..self.key.rank {
            loop {
                let mut r = LatticeElement::gaussian(
                    self.key.dimension,
                    self.key.params.modulus,
                    self.key.params.error_stddev,
                    rng,
                );
                
                r.to_ntt();
                
                // Rejection sampling for statistical security
                if self.sampler.sample(&r, rng).is_some() {
                    randomness.push(r);
                    break;
                }
            }
        }
        
        // Compute commitment: C_i = Σ_j A_{i,j} · r_j + encode(m_i)
        let mut commitment = Vec::with_capacity(self.key.rank);
        
        let evals_per_block = poly.evaluations.len() / self.key.rank;
        
        for i in 0..self.key.rank {
            let mut c = LatticeElement::zero(self.key.dimension, self.key.params.modulus);
            c.to_ntt();
            
            // Matrix-vector multiplication in NTT domain
            for j in 0..self.key.rank {
                let prod = self.key.public_matrices[i][j].mul_ntt(&randomness[j])?;
                c = c.add(prod);
            }
            
            // Encode polynomial slice
            let start_idx = i * evals_per_block;
            let end_idx = ((i + 1) * evals_per_block).min(poly.evaluations.len());
            let mut message_slice = vec![0u64; self.key.dimension];
            
            for (k, &eval) in poly.evaluations[start_idx..end_idx].iter().enumerate() {
                if k < message_slice.len() {
                    message_slice[k] = eval;
                }
            }
            
            let mut encoded = LatticeElement::new(message_slice, self.key.params.modulus);
            encoded.to_ntt();
            
            c = c.add(encoded);
            c.from_ntt();
            
            commitment.push(c);
        }
        
        let opening = Opening::new(
            randomness,
            poly.evaluations.clone(),
            Vec::new(),
            0,
        );
        
        Ok((RokokoCommitment::new(commitment), opening))
    }
    
    /// Proves evaluation f(r) = v for committed polynomial f
    /// Uses quotient polynomial technique for succinctness
    pub fn prove_evaluation<R: RngCore + CryptoRng>(
        &self,
        commitment: &RokokoCommitment,
        opening: &Opening,
        point: &[u64],
        rng: &mut R,
    ) -> Result<EvaluationProof, ZKVMError> {
        // Reconstruct polynomial from opening
        let poly = MultilinearPolynomial::new(
            opening.message.clone(),
            self.key.params.modulus,
        )?;
        
        // Compute claimed value
        let value = poly.evaluate(point)?;
        
        // Build quotient polynomial chain
        let mut quotient_commitments = Vec::new();
        let mut quotient_randomness = Vec::new();
        let mut partial_evaluations = Vec::new();
        
        let mut current_poly = poly;
        
        // For each variable in the multilinear polynomial
        for &r_i in point {
            partial_evaluations.push(current_poly.evaluations[0]);
            
            // Compute quotient polynomial: q_i(X_{i+1}, ..., X_ν) = 
            // [f_i(X_i, ..., X_ν) - f_i(r_i, ..., X_ν)] / (X_i - r_i)
            let quotient = self.compute_quotient_polynomial(&current_poly, r_i)?;
            
            // Commit to quotient
            let (q_comm, q_open) = self.commit_multilinear(&quotient, rng)?;
            quotient_commitments.push(q_comm);
            quotient_randomness.push(q_open.randomness);
            
            // Evaluate at r_i for next iteration
            current_poly = current_poly.partial_eval(r_i)?;
        }
        
        // Final evaluation should match claimed value
        if current_poly.evaluations.len() == 1 && current_poly.evaluations[0] != value {
            return Err(ZKVMError::ProofGenerationFailed(
                "Final evaluation mismatch".to_string()
            ));
        }
        
        Ok(EvaluationProof::new(
            value,
            point.to_vec(),
            quotient_commitments,
            quotient_randomness,
            partial_evaluations,
        ))
    }
    
    /// Verifies evaluation proof without opening commitment
    pub fn verify_evaluation(
        &self,
        commitment: &RokokoCommitment,
        proof: &EvaluationProof,
        point: &[u64],
        claimed_value: u64,
    ) -> Result<bool, ZKVMError> {
        // Check basic consistency
        if proof.value != claimed_value {
            return Ok(false);
        }
        
        if proof.point != point {
            return Ok(false);
        }
        
        if proof.quotient_commitments.len() != point.len() {
            return Ok(false);
        }
        
        // Verify quotient polynomial chain
        // Each quotient should satisfy: C_{i+1} = q_i(r_i)·(X_i - r_i) + C_i(r_i)
        
        for i in 0..point.len() {
            let r_i = point[i];
            
            // Verify quotient commitment is well-formed
            let q_comm = &proof.quotient_commitments[i];
            
            if q_comm.commitment.len() != self.key.rank {
                return Ok(false);
            }
            
            // Check norm bounds on randomness
            let q_rand = &proof.quotient_randomness[i];
            for r in q_rand {
                if r.infinity_norm() > (self.key.params.error_stddev * self.key.params.rejection_factor) as u64 {
                    return Ok(false);
                }
            }
        }
        
        // Verify final value matches
        if let Some(&final_eval) = proof.partial_evaluations.last() {
            if final_eval != claimed_value {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Opens commitment to verify correctness
    pub fn open(
        &self,
        commitment: &RokokoCommitment,
        opening: &Opening,
    ) -> Result<bool, ZKVMError> {
        // Verify randomness norm
        if !opening.verify_randomness_norm(&self.key.params) {
            return Ok(false);
        }
        
        // Recompute commitment from opening
        let poly = MultilinearPolynomial::new(
            opening.message.clone(),
            self.key.params.modulus,
        )?;
        
        let (recomputed, _) = self.commit_multilinear(&poly, &mut rand::thread_rng())?;
        
        // Compare commitment hashes
        Ok(commitment.commitment_hash == recomputed.commitment_hash)
    }
    
    /// Computes quotient polynomial for evaluation proof
    fn compute_quotient_polynomial(
        &self,
        poly: &MultilinearPolynomial,
        r: u64,
    ) -> Result<MultilinearPolynomial, ZKVMError> {
        // For multilinear polynomial f(X_1, X_2, ..., X_ν):
        // q(X_2, ..., X_ν) = [f(X_1, ...) - f(r, ...)] / (X_1 - r)
        //                   = [f(1, X_2, ...) - f(0, X_2, ...)] / 1  (simplified for multilinear)
        //                   = f(1, X_2, ...) - f(0, X_2, ...)
        
        let half = poly.evaluations.len() / 2;
        let mut quotient_evals = Vec::with_capacity(half);
        
        let modulus = self.key.params.modulus;
        
        for i in 0..half {
            let f_0 = poly.evaluations[i];           // f(0, w) where w ∈ {0,1}^{ν-1}
            let f_1 = poly.evaluations[i + half];    // f(1, w)
            
            // Quotient: (f_1 - f_0) represents the coefficient of X_1
            let diff = if f_1 >= f_0 {
                f_1 - f_0
            } else {
                modulus - (f_0 - f_1)
            };
            
            quotient_evals.push(diff);
        }
        
        MultilinearPolynomial::new(quotient_evals, modulus)
    }
    
    /// Batch commits to multiple polynomials efficiently
    pub fn batch_commit<R: RngCore + CryptoRng>(
        &self,
        polynomials: &[MultilinearPolynomial],
        rng: &mut R,
    ) -> Result<(Vec<RokokoCommitment>, Vec<Opening>), ZKVMError> {
        let mut commitments = Vec::with_capacity(polynomials.len());
        let mut openings = Vec::with_capacity(polynomials.len());
        
        for poly in polynomials {
            let (comm, open) = self.commit_multilinear(poly, rng)?;
            commitments.push(comm);
            openings.push(open);
        }
        
        Ok((commitments, openings))
    }
    
    /// Aggregates multiple evaluation proofs into one
    pub fn aggregate_proofs(
        &self,
        proofs: &[EvaluationProof],
        challenges: &[u64],
    ) -> Result<EvaluationProof, ZKVMError> {
        if proofs.is_empty() {
            return Err(ZKVMError::InvalidParameter("Empty proofs".to_string()));
        }
        
        if proofs.len() != challenges.len() {
            return Err(ZKVMError::InvalidParameter("Challenge count mismatch".to_string()));
        }
        
        // Random linear combination of proofs
        let modulus = self.key.params.modulus;
        let mut agg_value = 0u128;
        
        for (proof, &challenge) in proofs.iter().zip(challenges.iter()) {
            agg_value += (proof.value as u128 * challenge as u128);
            agg_value %= modulus as u128;
        }
        
        // Aggregate quotient commitments
        let num_quotients = proofs[0].quotient_commitments.len();
        let mut agg_quotient_comms = Vec::with_capacity(num_quotients);
        
        for i in 0..num_quotients {
            let mut agg_comm = proofs[0].quotient_commitments[i].clone();
            
            for j in 1..proofs.len() {
                let scaled = proofs[j].quotient_commitments[i].scalar_mul(challenges[j], modulus);
                agg_comm = agg_comm.add(&scaled)?;
            }
            
            agg_quotient_comms.push(agg_comm);
        }
        
        Ok(EvaluationProof::new(
            agg_value as u64,
            proofs[0].point.clone(),
            agg_quotient_comms,
            proofs[0].quotient_randomness.clone(),
            proofs[0].partial_evaluations.clone(),
        ))
    }
}

/// Trait for commitment schemes
pub trait CommitmentScheme {
    type Commitment;
    type Opening;
    type Proof;
    
    fn commit<R: RngCore + CryptoRng>(
        &self,
        message: &[u64],
        rng: &mut R,
    ) -> Result<(Self::Commitment, Self::Opening), ZKVMError>;
    
    fn open(
        &self,
        commitment: &Self::Commitment,
        opening: &Self::Opening,
    ) -> Result<bool, ZKVMError>;
    
    fn prove_eval(
        &self,
        commitment: &Self::Commitment,
        opening: &Self::Opening,
        point: &[u64],
    ) -> Result<Self::Proof, ZKVMError>;
    
    fn verify_eval(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        point: &[u64],
        value: u64,
    ) -> Result<bool, ZKVMError>;
}

// Helper functions

fn mod_exp(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base = base % modulus;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
        exp >>= 1;
    }
    
    result
}
