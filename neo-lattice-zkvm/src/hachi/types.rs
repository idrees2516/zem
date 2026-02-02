// Core type definitions for Hachi

use crate::field::Field;
use crate::ring::RingElement;

/// Multilinear polynomial over extension field
/// 
/// **Paper Reference:** Section 2.2 "Multilinear Extensions"
/// 
/// Represents f ∈ F_{q^k}^{≤1}[X_1, ..., X_ℓ] as coefficient vector
#[derive(Clone, Debug)]
pub struct MultilinearPolynomial<F: Field> {
    /// Number of variables ℓ
    pub num_variables: usize,
    
    /// Coefficients indexed by {0,1}^ℓ
    /// coeffs[i] corresponds to monomial ∏_{j: i_j=1} X_j
    pub coeffs: Vec<F>,
}

impl<F: Field> MultilinearPolynomial<F> {
    /// Create new multilinear polynomial
    pub fn new(num_variables: usize, coeffs: Vec<F>) -> Self {
        assert_eq!(coeffs.len(), 1 << num_variables,
            "Coefficient count must be 2^num_variables");
        Self { num_variables, coeffs }
    }
    
    /// Evaluate at point
    pub fn evaluate(&self, point: &[F]) -> F {
        assert_eq!(point.len(), self.num_variables);
        
        let mut result = F::zero();
        for (i, coeff) in self.coeffs.iter().enumerate() {
            let mut term = *coeff;
            for j in 0..self.num_variables {
                let bit = (i >> j) & 1;
                if bit == 1 {
                    term = term.mul(&point[j]);
                } else {
                    term = term.mul(&(F::one().sub(&point[j])));
                }
            }
            result = result.add(&term);
        }
        result
    }
}

/// Evaluation point for multilinear polynomial
#[derive(Clone, Debug)]
pub struct EvaluationPoint<F: Field> {
    pub coordinates: Vec<F>,
}

/// Evaluation claim: f(x) = y
#[derive(Clone, Debug)]
pub struct EvaluationClaim<F: Field> {
    pub point: EvaluationPoint<F>,
    pub value: F,
}

/// Commitment to multilinear polynomial
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolynomialCommitment<F: Field> {
    /// Inner-outer commitment value
    pub value: Vec<RingElement<F>>,
    
    /// Tracked witness norm bound
    pub witness_norm_bound: Option<f64>,
}

/// Opening for polynomial commitment
#[derive(Clone, Debug)]
pub struct PolynomialOpening<F: Field> {
    /// Witness vector
    pub witness: Vec<RingElement<F>>,
    
    /// Challenge scalar
    pub challenge: RingElement<F>,
}

/// Evaluation proof
#[derive(Clone, Debug)]
pub struct EvaluationProof<F: Field> {
    /// Ring switching components
    pub ring_switching: RingSwitchingProof<F>,
    
    /// Sumcheck proof
    pub sumcheck: SumcheckProof<F>,
    
    /// Norm verification proof
    pub norm_verification: NormVerificationProof<F>,
    
    /// Recursive evaluation proof (if applicable)
    pub recursive: Option<Box<EvaluationProof<F>>>,
}

/// Ring switching proof components
#[derive(Clone, Debug)]
pub struct RingSwitchingProof<F: Field> {
    /// MLE commitment
    pub mle_commitment: PolynomialCommitment<F>,
    
    /// Challenge α ∈ F_{q^k}
    pub challenge: Vec<F>, // Extension field element as vector
    
    /// Substitution result
    pub substitution_result: Vec<F>,
}

/// Sumcheck proof
#[derive(Clone, Debug)]
pub struct SumcheckProof<F: Field> {
    /// Round polynomials g_j(X) for j = 1, ..., μ
    pub round_polynomials: Vec<UnivariatePolynomial<F>>,
    
    /// Final evaluation P(r_1, ..., r_μ)
    pub final_evaluation: F,
    
    /// Challenges r_j for j = 1, ..., μ
    pub challenges: Vec<F>,
}

/// Univariate polynomial over extension field
#[derive(Clone, Debug)]
pub struct UnivariatePolynomial<F: Field> {
    /// Coefficients [c_0, c_1, ..., c_d]
    /// Represents c_0 + c_1·X + ... + c_d·X^d
    pub coeffs: Vec<F>,
}

impl<F: Field> UnivariatePolynomial<F> {
    /// Evaluate at point
    pub fn evaluate(&self, point: &F) -> F {
        let mut result = F::zero();
        let mut power = F::one();
        
        for coeff in &self.coeffs {
            result = result.add(&coeff.mul(&power));
            power = power.mul(point);
        }
        
        result
    }
    
    /// Degree of polynomial
    pub fn degree(&self) -> usize {
        self.coeffs.len().saturating_sub(1)
    }
}

/// Norm verification proof
#[derive(Clone, Debug)]
pub struct NormVerificationProof<F: Field> {
    /// Range proofs for each coordinate
    pub range_proofs: Vec<RangeProof<F>>,
    
    /// Zero-coefficient proofs
    pub zero_coeff_proofs: Vec<ZeroCoefficientProof<F>>,
}

/// Range proof for ||z_i|| ≤ β
#[derive(Clone, Debug)]
pub struct RangeProof<F: Field> {
    /// Coordinate index
    pub index: usize,
    
    /// Bound β
    pub bound: f64,
    
    /// Proof data
    pub proof_data: Vec<F>,
}

/// Zero-coefficient proof
#[derive(Clone, Debug)]
pub struct ZeroCoefficientProof<F: Field> {
    /// Polynomial with zero constant coefficient
    pub polynomial: UnivariatePolynomial<F>,
    
    /// Evaluation points
    pub eval_points: Vec<F>,
    
    /// Evaluation values
    pub eval_values: Vec<F>,
}

/// Public parameters for Hachi
#[derive(Clone, Debug)]
pub struct PublicParameters<F: Field> {
    /// Hachi parameters
    pub params: super::params::HachiParams,
    
    /// Commitment key
    pub commitment_key: CommitmentKey<F>,
    
    /// Extension field parameters
    pub extension_field_params: ExtensionFieldParams,
}

/// Commitment key
#[derive(Clone, Debug)]
pub struct CommitmentKey<F: Field> {
    /// Inner commitment matrix A_in ∈ R_q^{κ_in × n_in}
    pub matrix_inner: Vec<Vec<RingElement<F>>>,
    
    /// Outer commitment matrix A_out ∈ R_q^{κ_out × n_out}
    pub matrix_outer: Vec<Vec<RingElement<F>>>,
    
    /// Dimensions
    pub kappa_inner: usize,
    pub n_inner: usize,
    pub kappa_outer: usize,
    pub n_outer: usize,
}

/// Extension field parameters
#[derive(Clone, Debug)]
pub struct ExtensionFieldParams {
    /// Extension degree k
    pub degree: usize,
    
    /// Irreducible polynomial coefficients
    pub irreducible_poly: Vec<u64>,
    
    /// Frobenius automorphism precomputed powers
    pub frobenius_powers: Vec<Vec<u64>>,
}

/// Transcript for Fiat-Shamir
#[derive(Clone, Debug)]
pub struct Transcript {
    /// Internal state
    state: Vec<u8>,
}

impl Transcript {
    /// Create new transcript
    pub fn new(label: &[u8]) -> Self {
        Self {
            state: label.to_vec(),
        }
    }
    
    /// Append message
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.state.extend_from_slice(label);
        self.state.extend_from_slice(message);
    }
    
    /// Challenge scalar
    pub fn challenge_scalar<F: Field>(&mut self, label: &[u8]) -> F {
        use sha3::{Digest, Sha3_256};
        
        self.append_message(label, &[]);
        let mut hasher = Sha3_256::new();
        hasher.update(&self.state);
        let hash = hasher.finalize();
        
        // Convert hash to field element
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash[0..8]);
        let val = u64::from_le_bytes(bytes);
        
        F::from_u64(val % F::MODULUS)
    }
    
    /// Challenge vector
    pub fn challenge_vector<F: Field>(&mut self, label: &[u8], len: usize) -> Vec<F> {
        (0..len).map(|i| {
            let mut label_with_index = label.to_vec();
            label_with_index.extend_from_slice(&i.to_le_bytes());
            self.challenge_scalar(&label_with_index)
        }).collect()
    }
}
