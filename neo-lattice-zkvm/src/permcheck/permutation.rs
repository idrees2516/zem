// Permutation Representation and Indicator Functions
//
// This module implements permutation representations and their multilinear extensions,
// which are central to the permutation check protocols.
//
// # Key Concepts (Paper Section 2.2)
//
// ## Permutation σ: B^μ → B^μ
// A bijection on the boolean hypercube, represented as a mapping vector.
//
// ## Multilinear Extension σ̃
// For each bit i ∈ [μ], we compute σ̃ᵢ: F^μ → F, the MLE of the i-th bit of σ.
// This gives us σ̃(X) = (σ̃₁(X), ..., σ̃μ(X))
//
// ## Interpolated Polynomial σ̃[μ]
// A single polynomial σ̃[μ]: F^{μ+log μ} → F where σ̃[μ](⟨i⟩, X) = σ̃ᵢ(X)
// This allows querying any bit of the permutation with a single polynomial.
//
// ## Indicator Function 1_σ(X,Y)
// Equals 1 if σ(X) = Y, else 0. Arithmetized as:
//   1̃_σ(X,Y) = eq(σ̃(X), Y) = ∏ᵢ eq(σ̃ᵢ(X), Yᵢ)

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use crate::permcheck::foundation::EqualityPolynomial;
use crate::permcheck::errors::PermCheckError;
use std::collections::HashSet;

/// Permutation σ: [n] → [n] represented as a mapping
///
/// A permutation is a bijection on the set [n] = {0, 1, ..., n-1}.
/// We represent it as a vector where mapping[i] = σ(i).
///
/// # Paper Reference
/// Section 2.2: "Let σ: B^μ → B^μ be a permutation"
#[derive(Clone, Debug)]
pub struct Permutation {
    pub size: usize,
    pub mapping: Vec<usize>,
}


impl Permutation {
    /// Create a new permutation from a mapping vector
    ///
    /// # Arguments
    /// - `mapping`: Vector where mapping[i] = σ(i)
    ///
    /// # Returns
    /// Result containing the permutation or an error if invalid
    ///
    /// # Validation
    /// Checks that the mapping is a valid bijection:
    /// - Size is a power of 2 (required for boolean hypercube)
    /// - All values in [0, n)
    /// - No duplicates (bijection property)
    pub fn new(mapping: Vec<usize>) -> Result<Self, PermCheckError> {
        let size = mapping.len();
        
        // Validate size is power of 2
        if !size.is_power_of_two() {
            return Err(PermCheckError::InvalidPermutation {
                reason: format!("Size {} is not a power of 2", size),
            });
        }
        
        // Validate all values are in range
        for &val in &mapping {
            if val >= size {
                return Err(PermCheckError::InvalidPermutation {
                    reason: format!("Value {} out of range [0, {})", val, size),
                });
            }
        }
        
        // Validate bijection (no duplicates)
        let unique: HashSet<_> = mapping.iter().copied().collect();
        if unique.len() != size {
            return Err(PermCheckError::InvalidPermutation {
                reason: "Mapping contains duplicates (not a bijection)".to_string(),
            });
        }
        
        Ok(Self { size, mapping })
    }
    
    /// Create the identity permutation σ(i) = i
    pub fn identity(size: usize) -> Self {
        assert!(size.is_power_of_two());
        Self {
            size,
            mapping: (0..size).collect(),
        }
    }

    
    /// Compute the inverse permutation τ = σ^{-1}
    ///
    /// For a permutation σ, the inverse τ satisfies τ(σ(i)) = i for all i.
    ///
    /// # Paper Reference
    /// Section 4.1 (Prover-Provided Permutation):
    /// "The prover additionally commits to the inverse τ̃[μ] where τ = σ^{-1}"
    pub fn inverse(&self) -> Self {
        let mut inv_mapping = vec![0; self.size];
        for (i, &sigma_i) in self.mapping.iter().enumerate() {
            inv_mapping[sigma_i] = i;
        }
        
        Self {
            size: self.size,
            mapping: inv_mapping,
        }
    }
    
    /// Compose two permutations: (σ ∘ τ)(x) = σ(τ(x))
    pub fn compose(&self, other: &Self) -> Result<Self, PermCheckError> {
        if self.size != other.size {
            return Err(PermCheckError::PermutationSizeMismatch {
                expected: self.size,
                got: other.size,
            });
        }
        
        let composed = other.mapping.iter()
            .map(|&i| self.mapping[i])
            .collect();
        
        Ok(Self {
            size: self.size,
            mapping: composed,
        })
    }
    
    /// Check if this is a valid permutation
    pub fn is_valid(&self) -> bool {
        let unique: HashSet<_> = self.mapping.iter().copied().collect();
        unique.len() == self.size && 
        self.mapping.iter().all(|&x| x < self.size)
    }
    
    /// Number of variables μ where n = 2^μ
    pub fn num_vars(&self) -> usize {
        self.size.trailing_zeros() as usize
    }
}


/// Multilinear Extension of a Permutation
///
/// For a permutation σ: B^μ → B^μ, we compute the MLE of each output bit.
/// This gives us σ̃(X) = (σ̃₁(X), ..., σ̃μ(X)) where each σ̃ᵢ is multilinear.
///
/// # Construction (Paper Section 2.2)
/// For each bit position i ∈ [μ]:
///   σ̃ᵢ(X) = MLE of the function x ↦ i-th bit of σ(x)
///
/// # Example
/// If σ(5) = 3 in binary: σ(101) = (011)
/// Then: σ̃₁(101) = 1, σ̃₂(101) = 1, σ̃₃(101) = 0
///
/// # Paper Reference
/// Definition 2.2: "We denote by σ̃ᵢ the multilinear extension of the i-th bit of σ"
#[derive(Clone, Debug)]
pub struct PermutationMLE<F: Field> {
    pub num_vars: usize,
    /// σ̃ᵢ(X) for each bit i ∈ [μ]
    pub bit_mles: Vec<MultilinearPolynomial<F>>,
}

impl<F: Field> PermutationMLE<F> {
    /// Compute the multilinear extension of a permutation
    ///
    /// # Algorithm
    /// For each bit position i:
    /// 1. Extract the i-th bit of σ(x) for all x ∈ B^μ
    /// 2. Compute the MLE of this boolean function
    ///
    /// # Complexity
    /// O(μ · n) where n = 2^μ
    ///
    /// # Paper Reference
    /// Used throughout; explicit in Section 3 for BiPerm and MulPerm
    pub fn from_permutation(perm: &Permutation) -> Self {
        let num_vars = perm.num_vars();
        let mut bit_mles = Vec::with_capacity(num_vars);
        
        // For each bit position
        for bit_idx in 0..num_vars {
            // Extract bit_idx-th bit of σ(x) for all x
            let bit_values: Vec<F> = perm.mapping.iter()
                .map(|&sigma_x| {
                    let bit = (sigma_x >> bit_idx) & 1;
                    if bit == 1 { F::one() } else { F::zero() }
                })
                .collect();
            
            bit_mles.push(MultilinearPolynomial::new(bit_values));
        }
        
        Self { num_vars, bit_mles }
    }

    
    /// Interpolate into single polynomial σ̃[μ](I, X)
    ///
    /// Creates a (μ + log μ)-variate polynomial where:
    ///   σ̃[μ](⟨i⟩, X) = σ̃ᵢ(X) for all i ∈ [μ]
    ///
    /// This allows querying any bit of the permutation with a single polynomial,
    /// which is crucial for MulPerm's efficiency.
    ///
    /// # Construction
    /// σ̃[μ](I, X) = ∑_{i∈[μ]} eq(I, ⟨i⟩) · σ̃ᵢ(X)
    ///
    /// where ⟨i⟩ is the binary encoding of i using log μ bits.
    ///
    /// # Complexity
    /// O(μ · n · log μ) to construct the full evaluation table
    ///
    /// # Paper Reference
    /// Section 2.2, Equation (2.2):
    /// "We interpolate the μ polynomials into a single polynomial σ̃[μ]"
    ///
    /// Used extensively in MulPerm (Section 3.2)
    pub fn interpolate(&self) -> MultilinearPolynomial<F> {
        let mu = self.num_vars;
        let log_mu = (mu as f64).log2().ceil() as usize;
        let n = 1 << mu;
        let total_vars = mu + log_mu;
        let total_size = 1 << total_vars;
        
        let mut evaluations = vec![F::zero(); total_size];
        
        // For each index i ∈ [μ] and point x ∈ B^μ
        for i in 0..mu {
            // Binary encoding of i
            let i_binary: Vec<bool> = (0..log_mu)
                .map(|bit| (i >> bit) & 1 == 1)
                .collect();
            
            // For each x ∈ B^μ
            for x in 0..n {
                // Combined index: (x, i) in lexicographic order
                // x occupies lower μ bits, i occupies upper log μ bits
                let combined_idx = x | (i << mu);
                
                // σ̃[μ](⟨i⟩, x) = σ̃ᵢ(x)
                evaluations[combined_idx] = self.bit_mles[i].evaluations[x];
            }
        }
        
        MultilinearPolynomial::new(evaluations)
    }

    
    /// Evaluate σ̃(x) = (σ̃₁(x), ..., σ̃μ(x))
    ///
    /// Computes the multilinear extension of the permutation at a point x ∈ F^μ.
    /// Returns a vector of μ field elements representing the output.
    ///
    /// # Arguments
    /// - `x`: Point in F^μ
    ///
    /// # Returns
    /// Vector of μ field elements: [σ̃₁(x), σ̃₂(x), ..., σ̃μ(x)]
    ///
    /// # Complexity
    /// O(μ · n) where n = 2^μ (due to μ MLE evaluations)
    pub fn evaluate_map(&self, x: &[F]) -> Vec<F> {
        assert_eq!(x.len(), self.num_vars);
        self.bit_mles.iter()
            .map(|mle| mle.evaluate(x))
            .collect()
    }
}


/// Indicator Function 1_σ(X,Y)
///
/// The indicator function equals 1 when σ(X) = Y and 0 otherwise.
/// Its arithmetization is central to the permutation check protocols.
///
/// # Definition (Paper Section 2.2)
/// For X,Y ∈ B^μ:
///   1_σ(X,Y) = 1 if σ(X) = Y, else 0
///
/// # Arithmetization
/// The multilinear extension is:
///   1̃_σ(X,Y) = eq(σ̃(X), Y) = ∏_{i=1}^μ eq(σ̃ᵢ(X), Yᵢ)
///
/// This is a μ-way product, which is expensive to compute directly.
/// The key insight of BiPerm and MulPerm is to split this product differently.
///
/// # Paper Reference
/// Definition 2.3: "The indicator function 1_σ: B^μ × B^μ → {0,1}"
#[derive(Clone, Debug)]
pub struct IndicatorFunction<F: Field> {
    pub permutation_mle: PermutationMLE<F>,
}

impl<F: Field> IndicatorFunction<F> {
    /// Create indicator function from a permutation
    pub fn new(perm: &Permutation) -> Self {
        Self {
            permutation_mle: PermutationMLE::from_permutation(perm),
        }
    }
    
    /// Evaluate 1̃_σ(x, y) = eq(σ̃(x), y)
    ///
    /// # Arguments
    /// - `x`: First argument in F^μ
    /// - `y`: Second argument in F^μ
    ///
    /// # Returns
    /// The value 1̃_σ(x, y) ∈ F
    ///
    /// # Complexity
    /// O(μ · n) for evaluation (due to σ̃(x) computation)
    pub fn evaluate(&self, x: &[F], y: &[F]) -> F {
        let sigma_x = self.permutation_mle.evaluate_map(x);
        EqualityPolynomial::evaluate(&sigma_x, y)
    }
}


/// Arithmetization Strategy for Indicator Function
///
/// Different ways to split the μ-way product in 1̃_σ(X,Y) = ∏ᵢ eq(σ̃ᵢ(X), Yᵢ)
///
/// # Strategies
///
/// ## Naive (μ-way product)
/// Directly compute the μ-way product. This is the baseline approach.
/// - Degree: μ in each variable
/// - Prover time: O(n · μ) per sumcheck round → O(n · μ²) total
/// - Paper Reference: Section 2.3, used as baseline for comparison
///
/// ## BiPerm (2-way split)
/// Split into left and right halves:
///   1̃_σ(X,Y) = 1̃_{σ_L}(X, Y_L) · 1̃_{σ_R}(X, Y_R)
/// - Degree: 3 in each variable (optimal for sparse PCS)
/// - Prover time: O(n) with sparse PCS
/// - Paper Reference: Section 3.1, Theorem 3.1
///
/// ## MulPerm (ℓ-way split)
/// Split into ℓ groups where ℓ = √μ:
///   1̃_σ(X,Y) = ∏_{j=1}^ℓ 1̃_j(X, Y^{(j)})
/// - Degree: ℓ+1 in first sumcheck, μ/ℓ+1 in second
/// - Prover time: O(n · Õ(√log n)) with any PCS
/// - Paper Reference: Section 3.2, Theorem 3.2
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArithmetizationStrategy {
    /// Naive μ-way product (baseline)
    Naive,
    
    /// BiPerm: 2-way split (requires sparse PCS)
    BiPerm,
    
    /// MulPerm: ℓ-way split (works with any PCS)
    MulPerm { ell: usize },
}

impl ArithmetizationStrategy {
    /// Choose optimal strategy based on available PCS
    ///
    /// # Arguments
    /// - `num_vars`: Number of variables μ
    /// - `has_sparse_pcs`: Whether a sparse PCS is available
    ///
    /// # Returns
    /// Recommended strategy
    ///
    /// # Paper Reference
    /// Section 3.3: "BiPerm requires sparse PCS, MulPerm works with any PCS"
    pub fn choose_optimal(num_vars: usize, has_sparse_pcs: bool) -> Self {
        if has_sparse_pcs {
            // BiPerm is optimal with sparse PCS: O(n) prover time
            Self::BiPerm
        } else {
            // MulPerm with ℓ = √μ: O(n · Õ(√log n)) prover time
            let ell = (num_vars as f64).sqrt().ceil() as usize;
            Self::MulPerm { ell }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_identity_permutation() {
        let perm = Permutation::identity(8);
        assert_eq!(perm.size, 8);
        assert!(perm.is_valid());
        
        for i in 0..8 {
            assert_eq!(perm.mapping[i], i);
        }
    }
    
    #[test]
    fn test_permutation_inverse() {
        let mapping = vec![2, 0, 3, 1]; // σ: 0→2, 1→0, 2→3, 3→1
        let perm = Permutation::new(mapping).unwrap();
        let inv = perm.inverse();
        
        // Check τ(σ(i)) = i for all i
        for i in 0..4 {
            let sigma_i = perm.mapping[i];
            let tau_sigma_i = inv.mapping[sigma_i];
            assert_eq!(tau_sigma_i, i, "Inverse property failed at i={}", i);
        }
    }
    
    #[test]
    fn test_invalid_permutation_not_power_of_two() {
        let mapping = vec![0, 1, 2]; // Size 3, not power of 2
        assert!(Permutation::new(mapping).is_err());
    }
    
    #[test]
    fn test_invalid_permutation_duplicates() {
        let mapping = vec![0, 1, 1, 3]; // Duplicate 1
        assert!(Permutation::new(mapping).is_err());
    }
    
    #[test]
    fn test_permutation_mle_construction() {
        let mapping = vec![2, 0, 3, 1]; // 4 elements, μ=2
        let perm = Permutation::new(mapping).unwrap();
        let mle = PermutationMLE::<GoldilocksField>::from_permutation(&perm);
        
        assert_eq!(mle.num_vars, 2);
        assert_eq!(mle.bit_mles.len(), 2);
        
        // Check bit 0: [0,1,1,0] (LSB of [2,0,3,1])
        assert_eq!(mle.bit_mles[0].evaluations[0], GoldilocksField::zero());
        assert_eq!(mle.bit_mles[0].evaluations[1], GoldilocksField::zero());
        assert_eq!(mle.bit_mles[0].evaluations[2], GoldilocksField::one());
        assert_eq!(mle.bit_mles[0].evaluations[3], GoldilocksField::one());
        
        // Check bit 1: [1,0,1,0] (MSB of [2,0,3,1])
        assert_eq!(mle.bit_mles[1].evaluations[0], GoldilocksField::one());
        assert_eq!(mle.bit_mles[1].evaluations[1], GoldilocksField::zero());
        assert_eq!(mle.bit_mles[1].evaluations[2], GoldilocksField::one());
        assert_eq!(mle.bit_mles[1].evaluations[3], GoldilocksField::zero());
    }
    
    #[test]
    fn test_indicator_function_identity() {
        let perm = Permutation::identity(4);
        let indicator = IndicatorFunction::<GoldilocksField>::new(&perm);
        
        // For identity permutation: 1_σ(x,y) = 1 iff x = y
        let x = vec![GoldilocksField::from_u64(3), GoldilocksField::from_u64(5)];
        let y_same = vec![GoldilocksField::from_u64(3), GoldilocksField::from_u64(5)];
        let y_diff = vec![GoldilocksField::from_u64(2), GoldilocksField::from_u64(7)];
        
        let result_same = indicator.evaluate(&x, &y_same);
        let result_diff = indicator.evaluate(&x, &y_diff);
        
        // For identity: should behave like eq(x,y)
        assert_eq!(result_same, EqualityPolynomial::evaluate(&x, &y_same));
        assert_eq!(result_diff, EqualityPolynomial::evaluate(&x, &y_diff));
    }
}
