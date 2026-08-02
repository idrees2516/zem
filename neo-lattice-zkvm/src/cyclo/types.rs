//! Core types for the Cyclo folding scheme

use std::fmt;
use std::ops::{Add, Sub, Mul, Neg};
use crate::field::FiniteField;

// Add extension methods for FiniteField
pub trait FiniteFieldExt: FiniteField {
    fn from_i64(val: i64) -> Self;
    fn abs(&self) -> Self;
    fn pow(&self, exp: u64) -> Self;
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Self;
    fn modulus_u64() -> u64;
}

impl FiniteFieldExt for crate::field::GoldilocksField {
    fn from_i64(val: i64) -> Self {
        if val >= 0 {
            Self::from_u64(val as u64)
        } else {
            Self::from_u64((-val) as u64).neg()
        }
    }

    fn abs(&self) -> Self {
        *self // In prime field, all elements are already normalized
    }

    fn pow(&self, mut exp: u64) -> Self {
        let mut base = *self;
        let mut result = Self::one();
        
        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exp >>= 1;
        }
        
        result
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_u64().to_le_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut arr = [0u8; 8];
        let len = bytes.len().min(8);
        arr[..len].copy_from_slice(&bytes[..len]);
        Self::from_u64(u64::from_le_bytes(arr))
    }

    fn modulus_u64() -> u64 {
        // Goldilocks modulus: 2^64 - 2^32 + 1
        0xFFFFFFFF00000001u64
    }
}

/// Cyclotomic ring element R = Z[X]/⟨Φ_f(X)⟩
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingElement<F: FiniteField> {
    /// Coefficients in the powerful basis
    pub coeffs: Vec<F>,
    /// Conductor f
    pub conductor: usize,
    /// Degree φ = φ(f) (Euler's totient)
    pub degree: usize,
}

impl<F: FiniteField> RingElement<F> {
    pub fn new(coeffs: Vec<F>, conductor: usize) -> Self {
        let degree = euler_totient(conductor);
        assert_eq!(coeffs.len(), degree, "Coefficient count must match degree");
        Self { coeffs, conductor, degree }
    }

    pub fn zero(conductor: usize) -> Self {
        let degree = euler_totient(conductor);
        Self {
            coeffs: vec![F::zero(); degree],
            conductor,
            degree,
        }
    }

    pub fn one(conductor: usize) -> Self {
        let degree = euler_totient(conductor);
        let mut coeffs = vec![F::zero(); degree];
        coeffs[0] = F::one();
        Self { coeffs, conductor, degree }
    }

    /// Coefficient embedding: R → Z^φ
    pub fn cf(&self) -> Vec<F> {
        self.coeffs.clone()
    }

    /// Dual coefficient embedding for computing trace products
    pub fn cf_dual(&self) -> Vec<F> {
        let mut dual = vec![F::zero(); self.degree];
        dual[0] = self.coeffs[0];
        for i in 1..self.degree {
            dual[i] = F::zero() - self.coeffs[self.degree - i];
        }
        dual
    }

    /// Infinity norm (max absolute value of coefficients)
    pub fn norm_infinity(&self) -> F {
        self.coeffs.iter()
            .copied()
            .max_by(|a, b| {
                a.to_u64().cmp(&b.to_u64())
            })
            .unwrap_or(F::zero())
    }

    /// Add two ring elements
    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.conductor, other.conductor);
        let coeffs: Vec<F> = self.coeffs.iter()
            .zip(other.coeffs.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        Self::new(coeffs, self.conductor)
    }

    /// Multiply by scalar
    pub fn scalar_mul(&self, scalar: F) -> Self {
        let coeffs: Vec<F> = self.coeffs.iter()
            .map(|c| *c * scalar)
            .collect();
        Self::new(coeffs, self.conductor)
    }

    /// Inner product in the dual basis for trace computation
    pub fn trace_inner_product(&self, other: &Self) -> F {
        assert_eq!(self.degree, other.degree);
        let dual = self.cf_dual();
        dual.iter().zip(other.coeffs.iter())
            .map(|(a, b)| *a * *b)
            .fold(F::zero(), |acc, x| acc + x)
    }
}

/// Quotient ring R_q = R/qR
pub type RingElementMod<F> = RingElement<F>;

/// Extension field ring R_{q^e} = F_{q^e}[X]/⟨Φ_f(X)⟩
pub type ExtensionRingElement<F> = RingElement<F>;

/// Principal Linear Relation
/// Ξ^lin_{A,(M_i)_{i∈[k]},a,n,m,B}
#[derive(Clone, Debug)]
pub struct PrincipalLinearRelation<F: FiniteField> {
    /// Ajtai commitment matrix A ∈ R_q^{a×m}
    pub matrix_a: Vec<Vec<RingElement<F>>>,
    /// Constraint matrices (M_i)_{i∈[k]}
    pub matrices_m: Vec<Vec<Vec<RingElement<F>>>>,
    /// Rank parameters
    pub rank_a: usize,
    pub num_constraints: usize,
    pub num_evaluations: usize,
    pub witness_length: usize,
    /// Norm bound
    pub norm_bound: F,
}

/// Instance for Principal Linear Relation
#[derive(Clone, Debug)]
pub struct LinearInstance<F: FiniteField> {
    /// Challenge points (r_i)_{i∈[k]} ∈ R_{q^e}^{log m_i}
    pub challenge_points: Vec<Vec<ExtensionRingElement<F>>>,
    /// Evaluation points (b_i)_{i∈[n]} ∈ R_{q^e}^{log m}
    pub eval_points: Vec<Vec<ExtensionRingElement<F>>>,
    /// Image y ∈ R_q^{a+k+n}
    pub image: Vec<RingElement<F>>,
}

/// Witness for Principal Linear Relation
#[derive(Clone, Debug)]
pub struct LinearWitness<F: FiniteField> {
    /// Witness vector w ∈ R_q^m
    pub witness: Vec<RingElement<F>>,
}

/// Slacked Linear Relation (with short denominator s)
#[derive(Clone, Debug)]
pub struct SlackedLinearWitness<F: FiniteField> {
    pub witness: Vec<RingElement<F>>,
    /// Short denominator s ∈ R_q^×
    pub slack: RingElement<F>,
}

/// SIS-break relation (for extracting SIS solutions)
#[derive(Clone, Debug)]
pub struct SISInstance<F: FiniteField> {
    pub matrix_a: Vec<Vec<RingElement<F>>>,
    pub rank_a: usize,
    pub witness_length: usize,
    pub norm_bound: F,
}

/// Committed Hybrid R1CS Relation
#[derive(Clone, Debug)]
pub struct CommittedHybridR1CS<F: FiniteField> {
    /// R1CS matrices M_0, M_1, M_2 ∈ F_q^{m×m}
    pub matrices: [Vec<Vec<F>>; 3],
    /// Ajtai commitment matrix A ∈ R_q^{a×m}
    pub matrix_a: Vec<Vec<RingElement<F>>>,
    /// Parameters
    pub rank_a: usize,
    pub size_m: usize,
    pub public_length: usize,
    pub norm_bound: F,
}

/// Instance for Committed Hybrid R1CS
#[derive(Clone, Debug)]
pub struct HybridR1CSInstance<F: FiniteField> {
    /// Public input x ∈ R_q^ℓ
    pub public_input: Vec<RingElement<F>>,
    /// Commitment y = Az ∈ R_q^a
    pub commitment: Vec<RingElement<F>>,
}

/// Witness for Committed Hybrid R1CS
#[derive(Clone, Debug)]
pub struct HybridR1CSWitness<F: FiniteField> {
    /// Private witness w ∈ R_q^{m-ℓ-1}
    pub witness: Vec<RingElement<F>>,
}

/// Accumulator relation for folding
#[derive(Clone, Debug)]
pub struct AccumulatorRelation<F: FiniteField> {
    pub linear_relation: PrincipalLinearRelation<F>,
    /// Current accumulated norm bound β
    pub accumulated_norm: F,
}

/// Accumulator instance
#[derive(Clone, Debug)]
pub struct AccumulatorInstance<F: FiniteField> {
    pub linear_instance: LinearInstance<F>,
}

/// Accumulator witness
#[derive(Clone, Debug)]
pub struct AccumulatorWitness<F: FiniteField> {
    pub witness: Vec<RingElement<F>>,
}

/// Parameters for the Cyclo folding scheme
#[derive(Clone, Debug)]
pub struct CycloParams<F: FiniteField> {
    /// Cyclotomic conductor f
    pub conductor: usize,
    /// Prime modulus q
    pub modulus: F,
    /// Extension degree e for F_{q^e}
    pub extension_degree: usize,
    /// Decomposition base b
    pub base_b: usize,
    /// Initial norm bound B
    pub norm_bound_B: F,
    /// Rank of Ajtai commitment
    pub rank_a: usize,
    /// Extended rank a'
    pub rank_a_prime: usize,
    /// Witness length m
    pub witness_length: usize,
    /// Number of folding rounds allowed
    pub max_folding_rounds: usize,
    /// Expansion factor γ for challenges
    pub expansion_factor: F,
}

/// Proof transcript for range test
#[derive(Clone, Debug)]
pub struct RangeTestProof<F: FiniteField> {
    /// Sum-check proof
    pub sumcheck_proof: Vec<Vec<F>>,
    /// Final evaluation t̃
    pub final_eval: ExtensionRingElement<F>,
}

/// Proof transcript for extension commitment
#[derive(Clone, Debug)]
pub struct ExtensionCommitmentProof<F: FiniteField> {
    /// Extended commitment t = Rv
    pub commitment: Vec<RingElement<F>>,
}

/// Proof transcript for the folding scheme
#[derive(Clone, Debug)]
pub struct FoldingProof<F: FiniteField> {
    /// Extension commitment proofs for each input relation
    pub extension_proofs: Vec<ExtensionCommitmentProof<F>>,
    /// Range test proofs for each input relation
    pub range_proofs: Vec<RangeTestProof<F>>,
    /// Unification sum-check proof
    pub unification_proof: Vec<Vec<F>>,
    /// Evaluation claims
    pub evaluation_claims: Vec<ExtensionRingElement<F>>,
}

/// Compute Euler's totient function φ(n)
pub fn euler_totient(n: usize) -> usize {
    if n == 1 {
        return 1;
    }
    
    let mut result = n;
    let mut n = n;
    let mut p = 2;
    
    while p * p <= n {
        if n % p == 0 {
            while n % p == 0 {
                n /= p;
            }
            result -= result / p;
        }
        p += 1;
    }
    
    if n > 1 {
        result -= result / n;
    }
    
    result
}

/// Strong sampling set
#[derive(Clone, Debug)]
pub struct StrongSamplingSet<F: FiniteField> {
    /// Elements in the set
    pub elements: Vec<RingElement<F>>,
    /// Norm bound γ
    pub norm_bound: F,
    /// Non-unit probability (for approximate sets)
    pub non_unit_prob: f64,
}

impl<F: FiniteField> StrongSamplingSet<F> {
    /// Check if this is an exact or approximate strong sampling set
    pub fn is_exact(&self) -> bool {
        self.non_unit_prob == 0.0
    }
}

/// Distribution for sampling challenges
#[derive(Clone, Debug)]
pub enum ChallengeDistribution {
    /// Uniform over {-1, 0, 1}
    Ternary,
    /// Biased ternary with probability p for 0
    BiasedTernary { prob_zero: f64 },
    /// Uniform over {-1, 0, 1, 2}
    Quaternary,
    /// Uniform over subfield
    Subfield { size: usize },
}

/// Multilinear Extension (MLE)
#[derive(Clone, Debug)]
pub struct MLE<F: FiniteField> {
    /// Number of variables
    pub num_vars: usize,
    /// Evaluations on boolean hypercube
    pub evaluations: Vec<F>,
}

impl<F: FiniteField> MLE<F> {
    pub fn new(evaluations: Vec<F>) -> Self {
        let num_vars = (evaluations.len() as f64).log2().ceil() as usize;
        assert_eq!(evaluations.len(), 1 << num_vars);
        Self { num_vars, evaluations }
    }

    /// Evaluate MLE at a point
    pub fn evaluate(&self, point: &[F]) -> F {
        assert_eq!(point.len(), self.num_vars);
        
        let mut result = F::zero();
        for (i, eval) in self.evaluations.iter().enumerate() {
            let mut term = *eval;
            for j in 0..self.num_vars {
                let bit = (i >> j) & 1;
                if bit == 1 {
                    term = term * point[j];
                } else {
                    term = term * (F::one() - point[j]);
                }
            }
            result = result + term;
        }
        result
    }
}

/// Lagrange polynomial eq(x, t)
pub fn eq_polynomial<F: FiniteField>(x: &[F], t: &[F]) -> F {
    assert_eq!(x.len(), t.len());
    let mut result = F::one();
    for (xi, ti) in x.iter().zip(t.iter()) {
        result = result * (*xi * *ti + (F::one() - *xi) * (F::one() - *ti));
    }
    result
}

/// Tensor product for creating evaluation tensors
pub fn tensor<F: FiniteField>(t: &[F]) -> Vec<F> {
    let n = t.len();
    let size = 1 << n;
    let mut result = vec![F::zero(); size];
    
    for i in 0..size {
        let mut val = F::one();
        for j in 0..n {
            let bit = (i >> j) & 1;
            if bit == 1 {
                val = val * t[j];
            } else {
                val = val * (F::one() - t[j]);
            }
        }
        result[i] = val;
    }
    result
}
