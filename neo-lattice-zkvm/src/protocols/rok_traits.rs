// Reduction of Knowledge (RoK) Trait Definitions
// Core abstractions for protocol composition in Symphony

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::field::symphony_extension::SymphonyExtensionField;
use crate::ring::tensor::TensorElement;
use crate::commitment::ajtai::Commitment;
use crate::folding::transcript::Transcript;
use std::fmt::Debug;

/// Reduction of Knowledge protocol trait
/// Reduces checking one relation to checking another relation
pub trait ReductionOfKnowledge {
    type InputInstance: Clone + Debug;
    type InputWitness: Clone + Debug;
    type OutputInstance: Clone + Debug;
    type OutputWitness: Clone + Debug;
    type Proof: Clone + Debug;
    type Error: std::error::Error;
    
    /// Prover: reduce input instance/witness to output instance/witness
    fn reduce(
        &self,
        instance: &Self::InputInstance,
        witness: &Self::InputWitness,
        transcript: &mut Transcript,
    ) -> Result<(Self::OutputInstance, Self::OutputWitness, Self::Proof), Self::Error>;
    
    /// Verifier: verify reduction and obtain output instance
    fn verify(
        &self,
        instance: &Self::InputInstance,
        proof: &Self::Proof,
        transcript: &mut Transcript,
    ) -> Result<Self::OutputInstance, Self::Error>;
    
    /// Get protocol name for transcript labeling
    fn protocol_name(&self) -> &'static str;
}

/// Linear evaluation instance R_lin^aux
/// Checks: ⟨f, ts(r)⟩ = v AND commitment opening
#[derive(Clone, Debug)]
pub struct LinearInstance<F: Field> {
    /// Commitment to witness
    pub commitment: Commitment<F>,
    
    /// Public input (if any)
    pub public_input: Vec<RingElement<F>>,
    
    /// Evaluation point r ∈ K^{log n}
    pub evaluation_point: Vec<SymphonyExtensionField<F>>,
    
    /// Claimed evaluation v ∈ E (tensor element)
    pub evaluation: TensorElement<F>,
    
    /// Auxiliary data (challenge set, parameters, etc.)
    pub aux_data: LinearAuxData<F>,
}

/// Auxiliary data for linear instance
#[derive(Clone, Debug)]
pub struct LinearAuxData<F: Field> {
    /// Challenge set S
    pub challenge_set_size: usize,
    
    /// Norm bound B
    pub norm_bound: f64,
    
    /// Block size ℓ_h
    pub block_size: usize,
    
    /// Ring parameters
    pub ring: CyclotomicRing<F>,
}

/// Linear witness
#[derive(Clone, Debug)]
pub struct LinearWitness<F: Field> {
    /// Witness vector f ∈ Rq^n
    pub witness: Vec<RingElement<F>>,
    
    /// Opening scalar s ∈ S - S
    pub opening_scalar: RingElement<F>,
    
    /// Witness norm
    pub norm: f64,
}

/// Batch linear evaluation instance R_batchlin
/// Checks multiple linear evaluations with shared evaluation point
#[derive(Clone, Debug)]
pub struct BatchLinearInstance<F: Field> {
    /// Evaluation point r ∈ K^{log n}
    pub evaluation_point: Vec<SymphonyExtensionField<F>>,
    
    /// Commitments to witnesses
    pub commitments: Vec<Commitment<F>>,
    
    /// Claimed evaluations v_i ∈ E
    pub evaluations: Vec<TensorElement<F>>,
    
    /// Auxiliary data
    pub aux_data: LinearAuxData<F>,
}

/// Batch linear witness
#[derive(Clone, Debug)]
pub struct BatchLinearWitness<F: Field> {
    /// Witness vectors f_i ∈ Rq^n
    pub witnesses: Vec<Vec<RingElement<F>>>,
    
    /// Opening scalars s_i ∈ S - S
    pub opening_scalars: Vec<RingElement<F>>,
}

/// R1CS instance (standard form)
#[derive(Clone, Debug)]
pub struct R1CSInstance<F: Field> {
    /// Public input x ∈ F_q^{n_pub}
    pub public_input: Vec<F>,
    
    /// R1CS matrices (M_A, M_B, M_C)
    pub matrices: (SparseMatrix<F>, SparseMatrix<F>, SparseMatrix<F>),
    
    /// Number of constraints
    pub num_constraints: usize,
    
    /// Number of variables (including public input)
    pub num_variables: usize,
}

/// R1CS witness (standard form)
#[derive(Clone, Debug)]
pub struct R1CSWitness<F: Field> {
    /// Witness vector w ∈ F_q^{n_wit}
    pub witness: Vec<F>,
}

/// Sparse matrix representation for R1CS
#[derive(Clone, Debug)]
pub struct SparseMatrix<F: Field> {
    /// Number of rows
    pub rows: usize,
    
    /// Number of columns
    pub cols: usize,
    
    /// Non-zero entries: (row, col, value)
    pub entries: Vec<(usize, usize, F)>,
}

impl<F: Field> SparseMatrix<F> {
    /// Create new sparse matrix
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            entries: Vec::new(),
        }
    }
    
    /// Add entry to matrix
    pub fn add_entry(&mut self, row: usize, col: usize, value: F) {
        assert!(row < self.rows && col < self.cols);
        self.entries.push((row, col, value));
    }
    
    /// Matrix-vector multiplication: M * v
    pub fn multiply_vector(&self, v: &[F]) -> Vec<F> {
        assert_eq!(v.len(), self.cols);
        
        let mut result = vec![F::zero(); self.rows];
        
        for &(row, col, ref value) in &self.entries {
            result[row] = result[row].add(&value.mul(&v[col]));
        }
        
        result
    }
    
    /// Hadamard (element-wise) product with another matrix
    pub fn hadamard_product(&self, other: &Self) -> Self {
        assert_eq!(self.rows, other.rows);
        assert_eq!(self.cols, other.cols);
        
        // Convert to dense for Hadamard product
        let mut result = Self::new(self.rows, self.cols);
        
        // Build dense representation
        let mut dense_self = vec![vec![F::zero(); self.cols]; self.rows];
        for &(row, col, ref value) in &self.entries {
            dense_self[row][col] = *value;
        }
        
        let mut dense_other = vec![vec![F::zero(); other.cols]; other.rows];
        for &(row, col, ref value) in &other.entries {
            dense_other[row][col] = *value;
        }
        
        // Compute Hadamard product
        for row in 0..self.rows {
            for col in 0..self.cols {
                let product = dense_self[row][col].mul(&dense_other[row][col]);
                if product != F::zero() {
                    result.add_entry(row, col, product);
                }
            }
        }
        
        result
    }
}

/// Multilinear polynomial over extension field
#[derive(Clone, Debug)]
pub struct MultilinearPolynomial<F: Field> {
    /// Evaluations at Boolean hypercube {0,1}^k
    pub evaluations: Vec<SymphonyExtensionField<F>>,
    
    /// Number of variables k
    pub num_variables: usize,
}

impl<F: Field> MultilinearPolynomial<F> {
    /// Create from evaluations
    pub fn from_evaluations(evaluations: Vec<SymphonyExtensionField<F>>) -> Self {
        let num_variables = (evaluations.len() as f64).log2() as usize;
        assert_eq!(evaluations.len(), 1 << num_variables);
        
        Self {
            evaluations,
            num_variables,
        }
    }
    
    /// Evaluate at point r ∈ K^k
    pub fn evaluate(&self, r: &[SymphonyExtensionField<F>]) -> SymphonyExtensionField<F> {
        assert_eq!(r.len(), self.num_variables);
        
        // Compute tensor product ts(r) = ⊗_{i∈[k]} (1-r_i, r_i)
        let tensor = compute_tensor_product(r);
        
        // Compute inner product ⟨evaluations, tensor⟩
        let mut result = SymphonyExtensionField::zero();
        for (eval, tensor_elem) in self.evaluations.iter().zip(tensor.iter()) {
            result = result.add(&eval.mul(tensor_elem));
        }
        
        result
    }
}

/// Compute tensor product ts(r) = ⊗_{i∈[k]} (1-r_i, r_i)
pub fn compute_tensor_product<F: Field>(
    r: &[SymphonyExtensionField<F>]
) -> Vec<SymphonyExtensionField<F>> {
    let k = r.len();
    let size = 1 << k;
    
    let mut tensor = vec![SymphonyExtensionField::one()];
    
    for r_i in r {
        let mut new_tensor = Vec::with_capacity(tensor.len() * 2);
        let one_minus_r = SymphonyExtensionField::one().sub(r_i);
        
        for t in &tensor {
            new_tensor.push(t.mul(&one_minus_r));
            new_tensor.push(t.mul(r_i));
        }
        
        tensor = new_tensor;
    }
    
    assert_eq!(tensor.len(), size);
    tensor
}

/// Equality polynomial eq(b, x) = ∏_{i∈[k]} ((1-b_i)(1-x_i) + b_i·x_i)
pub fn compute_eq_polynomial<F: Field>(
    b: &[SymphonyExtensionField<F>],
    x: &[SymphonyExtensionField<F>],
) -> SymphonyExtensionField<F> {
    assert_eq!(b.len(), x.len());
    
    let mut result = SymphonyExtensionField::one();
    
    for (b_i, x_i) in b.iter().zip(x.iter()) {
        // Compute (1-b_i)(1-x_i) + b_i·x_i
        let one = SymphonyExtensionField::one();
        let one_minus_b = one.sub(b_i);
        let one_minus_x = one.sub(x_i);
        let term1 = one_minus_b.mul(&one_minus_x);
        let term2 = b_i.mul(x_i);
        let factor = term1.add(&term2);
        
        result = result.mul(&factor);
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_sparse_matrix_multiply() {
        let mut matrix = SparseMatrix::<GoldilocksField>::new(3, 3);
        matrix.add_entry(0, 0, GoldilocksField::one());
        matrix.add_entry(1, 1, GoldilocksField::from_u64(2));
        matrix.add_entry(2, 2, GoldilocksField::from_u64(3));
        
        let v = vec![
            GoldilocksField::one(),
            GoldilocksField::one(),
            GoldilocksField::one(),
        ];
        
        let result = matrix.multiply_vector(&v);
        assert_eq!(result[0], GoldilocksField::one());
        assert_eq!(result[1], GoldilocksField::from_u64(2));
        assert_eq!(result[2], GoldilocksField::from_u64(3));
    }
    
    #[test]
    fn test_tensor_product() {
        let r = vec![
            SymphonyExtensionField::<GoldilocksField>::one(),
            SymphonyExtensionField::<GoldilocksField>::zero(),
        ];
        
        let tensor = compute_tensor_product(&r);
        
        // tensor(1, 0) = [(1-1)(1-0), (1-1)·0, 1·(1-0), 1·0] = [0, 0, 1, 0]
        assert_eq!(tensor.len(), 4);
        assert_eq!(tensor[0], SymphonyExtensionField::zero());
        assert_eq!(tensor[1], SymphonyExtensionField::zero());
        assert_eq!(tensor[2], SymphonyExtensionField::one());
        assert_eq!(tensor[3], SymphonyExtensionField::zero());
    }
}
