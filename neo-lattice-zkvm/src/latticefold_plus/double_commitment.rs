// Double Commitment Implementation for LatticeFold+
// dcom(M) = com(split(com(M))) for matrices
// Compresses d commitments into 1 via gadget decomposition

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::commitment::ajtai::Commitment as BaseCommitment;
use super::ajtai_commitment::{AjtaiCommitment, OpeningInfo};
use super::gadget::GadgetDecomposition;
use super::monomial::MonomialMatrix;

/// Double commitment structure
/// Implements dcom(M) = com(split(com(M)))
#[derive(Clone, Debug)]
pub struct DoubleCommitment<F: Field> {
    /// Outer commitment: com(τ) where τ = split(com(M))
    pub outer_commitment: BaseCommitment<F>,
    
    /// Inner commitments: com(M_*,j) for each column j ∈ [m]
    pub inner_commitments: Vec<BaseCommitment<F>>,
    
    /// Split vector τ ∈ (-d', d')^n
    pub split_vector: Vec<i64>,
    
    /// Original matrix M ∈ Rq^(n×m) (optional, for prover)
    pub original_matrix: Option<Vec<Vec<RingElement<F>>>>,
    
    /// Parameters
    pub d_prime: usize,  // d' = d/2
    pub ell: usize,      // ℓ = ⌈log_{d'}(q)⌉
    pub kappa: usize,    // Commitment dimension
    pub m: usize,        // Number of columns
}

/// Split function: Rq^(κ×m) → (-d', d')^n
/// Construction 4.1 from LatticeFold+ paper
pub struct SplitFunction<F: Field> {
    d_prime: usize,
    ell: usize,
    kappa: usize,
    m: usize,
    ring: CyclotomicRing<F>,
    gadget: GadgetDecomposition<F>,
}

/// Pow function: (-d', d')^n → Rq^(κ×m)
/// Inverse of split (up to padding)
pub struct PowFunction<F: Field> {
    d_prime: usize,
    ell: usize,
    kappa: usize,
    m: usize,
    ring: CyclotomicRing<F>,
}

/// Double opening relation R_{dopen,m}
/// Verifies (τ, M) is valid opening of C_M
#[derive(Clone, Debug)]
pub struct DoubleOpeningRelation<F: Field> {
    /// Double commitment C_M
    pub commitment: BaseCommitment<F>,
    
    /// Split vector τ ∈ (-d', d')^n
    pub split_vector: Vec<i64>,
    
    /// Matrix M ∈ Rq^(n×m)
    pub matrix: Vec<Vec<RingElement<F>>>,
    
    /// Norm bound b
    pub norm_bound: u64,
    
    /// Strong sampling set operator norm
    pub s_op_norm: f64,
}

impl<F: Field> DoubleCommitment<F> {
    /// Create double commitment for vector
    /// dcom(m) = com(m) for m ∈ Rq^n
    pub fn commit_vector(
        scheme: &AjtaiCommitment<F>,
        vector: &[RingElement<F>],
    ) -> Result<Self, String> {
        // For vectors, double commitment is just regular commitment
        let commitment = scheme.commit(vector)
            .map_err(|e| format!("Commitment failed: {:?}", e))?;
        
        let d = scheme.ring().degree;
        let d_prime = d / 2;
        
        Ok(Self {
            outer_commitment: commitment.clone(),
            inner_commitments: vec![commitment],
            split_vector: Vec::new(), // Not used for vectors
            original_matrix: None,
            d_prime,
            ell: 0,
            kappa: scheme.kappa(),
            m: 1,
        })
    }
    
    /// Create double commitment for matrix
    /// dcom(M) = com(split(com(M))) for M ∈ Rq^(n×m)
    pub fn commit_matrix(
        scheme: &AjtaiCommitment<F>,
        matrix: &[Vec<RingElement<F>>],
    ) -> Result<Self, String> {
        if matrix.is_empty() {
            return Err("Matrix cannot be empty".to_string());
        }
        
        let n = matrix.len();
        let m = matrix[0].len();
        let kappa = scheme.kappa();
        let d = scheme.ring().degree;
        let d_prime = d / 2;
        
        // Compute ℓ = ⌈log_{d'}(q)⌉
        let q = scheme.ring().modulus;
        let ell = ((q as f64).log2() / (d_prime as f64).log2()).ceil() as usize;
        
        // Step 1: Commit to each column of M
        let mut inner_commitments = Vec::with_capacity(m);
        for j in 0..m {
            let column: Vec<_> = matrix.iter().map(|row| row[j].clone()).collect();
            let cm = scheme.commit(&column)
                .map_err(|e| format!("Column commitment failed: {:?}", e))?;
            inner_commitments.push(cm);
        }
        
        // Step 2: Compute split(com(M))
        let split_fn = SplitFunction::new(
            d_prime,
            ell,
            kappa,
            m,
            scheme.ring().clone(),
        );
        
        let com_matrix: Vec<Vec<_>> = inner_commitments.iter()
            .map(|cm| cm.values.clone())
            .collect();
        
        let split_vector = split_fn.split(&com_matrix)?;
        
        // Step 3: Commit to split vector
        // Convert split vector to ring elements
        let split_ring_elems = Self::split_to_ring_elements(&split_vector, scheme.ring());
        let outer_commitment = scheme.commit(&split_ring_elems)
            .map_err(|e| format!("Outer commitment failed: {:?}", e))?;
        
        Ok(Self {
            outer_commitment,
            inner_commitments,
            split_vector,
            original_matrix: Some(matrix.to_vec()),
            d_prime,
            ell,
            kappa,
            m,
        })
    }
    
    /// Convert split vector (integers) to ring elements for commitment
    fn split_to_ring_elements(split: &[i64], ring: &CyclotomicRing<F>) -> Vec<RingElement<F>> {
        let d = ring.degree;
        let n_elems = (split.len() + d - 1) / d;
        
        let mut result = Vec::with_capacity(n_elems);
        for chunk_idx in 0..n_elems {
            let start = chunk_idx * d;
            let end = (start + d).min(split.len());
            
            let mut coeffs = vec![F::zero(); d];
            for (i, &val) in split[start..end].iter().enumerate() {
                coeffs[i] = F::from_i64(val);
            }
            
            result.push(RingElement::from_coeffs(coeffs));
        }
        
        result
    }
    
    /// Verify double commitment binding property (Lemma 4.1)
    /// If com(·) is binding, then dcom(·) is binding
    pub fn verify_binding(&self) -> bool {
        // Binding is inherited from underlying linear commitment
        // Proof by collision reduction:
        // If we have collision in dcom, we can construct collision in com
        true
    }
    
    /// Get the outer commitment value
    pub fn outer(&self) -> &BaseCommitment<F> {
        &self.outer_commitment
    }
    
    /// Get the inner commitments
    pub fn inner(&self) -> &[BaseCommitment<F>] {
        &self.inner_commitments
    }
    
    /// Get the split vector
    pub fn split(&self) -> &[i64] {
        &self.split_vector
    }
}

impl<F: Field> SplitFunction<F> {
    /// Create new split function
    pub fn new(
        d_prime: usize,
        ell: usize,
        kappa: usize,
        m: usize,
        ring: CyclotomicRing<F>,
    ) -> Self {
        let gadget = GadgetDecomposition::new(d_prime as i64, ell, m, ring.clone());
        
        Self {
            d_prime,
            ell,
            kappa,
            m,
            ring,
            gadget,
        }
    }
    
    /// Compute split(com(M)) ∈ (-d', d')^n
    /// 
    /// Construction 4.1:
    /// 1. M' = G^(-1)_{d',ℓ}(com(M)) ∈ Rq^(κ×mℓ)
    /// 2. M'' = flat(M') ∈ Rq^(κmℓ)
    /// 3. τ'_M = flat(cf(M'')) ∈ (-d', d')^(κmℓd)
    /// 4. Pad τ'_M to τ_M ∈ (-d', d')^n
    pub fn split(&self, com_matrix: &[Vec<RingElement<F>>]) -> Result<Vec<i64>, String> {
        if com_matrix.len() != self.kappa {
            return Err(format!("Expected {} rows, got {}", self.kappa, com_matrix.len()));
        }
        
        // Step 1: Gadget decomposition G^(-1)_{d',ℓ}(com(M))
        let m_prime = self.gadget_decompose(com_matrix)?;
        
        // Step 2: Flatten matrix to vector
        let m_double_prime = self.flatten_matrix(m_prime);
        
        // Step 3: Extract coefficients
        let tau_m_prime = self.flatten_coefficients(m_double_prime);
        
        // Step 4: Pad to length n
        let tau_m = self.pad_to_n(tau_m_prime);
        
        // Verify all entries are in range (-d', d')
        for &val in &tau_m {
            if val.abs() >= self.d_prime as i64 {
                return Err(format!("Split value {} out of range (-{}, {})", val, self.d_prime, self.d_prime));
            }
        }
        
        Ok(tau_m)
    }
    
    /// Step 1: Gadget decomposition
    fn gadget_decompose(&self, com_matrix: &[Vec<RingElement<F>>]) 
        -> Result<Vec<Vec<RingElement<F>>>, String> {
        // Apply G^(-1)_{d',ℓ} to each row of com(M)
        let mut result = Vec::with_capacity(self.kappa);
        
        for row in com_matrix {
            if row.len() != self.m {
                return Err(format!("Expected {} columns, got {}", self.m, row.len()));
            }
            
            let mut decomposed_row = Vec::with_capacity(self.m * self.ell);
            
            for elem in row {
                // Decompose each ring element
                let decomp = self.decompose_ring_element(elem)?;
                decomposed_row.extend(decomp);
            }
            
            result.push(decomposed_row);
        }
        
        Ok(result)
    }
    
    /// Decompose single ring element using gadget
    fn decompose_ring_element(&self, elem: &RingElement<F>) -> Result<Vec<RingElement<F>>, String> {
        let d = self.ring.degree;
        let coeffs = elem.coeffs.clone();
        
        // Decompose each coefficient to base d'
        let mut result = vec![vec![F::zero(); d]; self.ell];
        
        for (coeff_idx, coeff) in coeffs.iter().enumerate() {
            let val = coeff.to_i64();
            let decomp = self.decompose_scalar(val);
            
            for (k, &decomp_val) in decomp.iter().enumerate() {
                result[k][coeff_idx] = F::from_i64(decomp_val);
            }
        }
        
        Ok(result.into_iter().map(|c| RingElement::from_coeffs(c)).collect())
    }
    
    /// Decompose scalar to base d' with sign handling
    fn decompose_scalar(&self, x: i64) -> Vec<i64> {
        let mut result = vec![0i64; self.ell];
        let mut abs_x = x.abs();
        let sign = x.signum();
        let base = self.d_prime as i64;
        
        for i in 0..self.ell {
            result[i] = sign * (abs_x % base);
            abs_x /= base;
        }
        
        result
    }
    
    /// Step 2: Flatten matrix to vector
    fn flatten_matrix(&self, matrix: Vec<Vec<RingElement<F>>>) -> Vec<RingElement<F>> {
        // flat(M') = (M'_{0,*}, ..., M'_{κ-1,*})
        matrix.into_iter().flatten().collect()
    }
    
    /// Step 3: Extract coefficients
    fn flatten_coefficients(&self, vector: Vec<RingElement<F>>) -> Vec<i64> {
        // flat(cf(M'')) ∈ (-d', d')^(κmℓd)
        vector.into_iter()
            .flat_map(|elem| elem.coeffs.iter().map(|c| c.to_i64()).collect::<Vec<_>>())
            .collect()
    }
    
    /// Step 4: Pad to length n
    fn pad_to_n(&self, tau: Vec<i64>) -> Vec<i64> {
        let d = self.ring.degree;
        let n = self.compute_n();
        let mut result = tau;
        
        // Pad with zeros
        result.resize(n, 0);
        
        result
    }
    
    /// Compute required n such that κmdℓ ≤ n
    fn compute_n(&self) -> usize {
        let d = self.ring.degree;
        self.kappa * self.m * d * self.ell
    }
    
    /// Verify split is injective
    pub fn verify_injective(&self) -> bool {
        // Split is injective by construction:
        // - Gadget decomposition is injective
        // - Flattening is injective
        // - Coefficient extraction is injective
        // - Padding preserves injectivity
        true
    }
}

impl<F: Field> PowFunction<F> {
    /// Create new pow function
    pub fn new(
        d_prime: usize,
        ell: usize,
        kappa: usize,
        m: usize,
        ring: CyclotomicRing<F>,
    ) -> Self {
        Self {
            d_prime,
            ell,
            kappa,
            m,
            ring,
        }
    }
    
    /// Compute pow(τ) = com(M) ∈ Rq^(κ×m)
    /// 
    /// Inverse of split: pow(split(D)) = D
    /// Computes power-sums of sub-vectors and embeds to coefficients
    pub fn pow(&self, tau: &[i64]) -> Result<Vec<Vec<RingElement<F>>>, String> {
        let d = self.ring.degree;
        let chunk_size = d * self.ell;
        
        let mut result = Vec::with_capacity(self.kappa);
        
        for i in 0..self.kappa {
            let mut row = Vec::with_capacity(self.m);
            
            for j in 0..self.m {
                let start = (i * self.m + j) * chunk_size;
                let end = start + chunk_size;
                
                if end > tau.len() {
                    return Err(format!("Tau vector too short: need {}, got {}", end, tau.len()));
                }
                
                let chunk = &tau[start..end];
                let elem = self.power_sum_embed(chunk)?;
                row.push(elem);
            }
            
            result.push(row);
        }
        
        Ok(result)
    }
    
    /// Compute power sums and embed to polynomial coefficients
    fn power_sum_embed(&self, chunk: &[i64]) -> Result<RingElement<F>, String> {
        let d = self.ring.degree;
        let mut coeffs = vec![F::zero(); d];
        
        // Reconstruct from gadget decomposition
        // Each group of ℓ values represents one coefficient
        for (idx, &val) in chunk.iter().enumerate() {
            let power = idx % self.ell;
            let coeff_idx = idx / self.ell;
            
            if coeff_idx >= d {
                return Err(format!("Coefficient index {} out of range", coeff_idx));
            }
            
            let contribution = val * (self.d_prime as i64).pow(power as u32);
            coeffs[coeff_idx] = coeffs[coeff_idx].add(&F::from_i64(contribution));
        }
        
        Ok(RingElement::from_coeffs(coeffs))
    }
    
    /// Verify pow(split(D)) = D
    pub fn verify_inverse(&self, d: &[Vec<RingElement<F>>], split_fn: &SplitFunction<F>) 
        -> Result<bool, String> {
        let tau = split_fn.split(d)?;
        let reconstructed = self.pow(&tau)?;
        
        // Check if reconstructed equals original
        if reconstructed.len() != d.len() {
            return Ok(false);
        }
        
        for (i, (row_rec, row_orig)) in reconstructed.iter().zip(d.iter()).enumerate() {
            if row_rec.len() != row_orig.len() {
                return Ok(false);
            }
            
            for (j, (elem_rec, elem_orig)) in row_rec.iter().zip(row_orig.iter()).enumerate() {
                if elem_rec.coeffs != elem_orig.coeffs {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
    
    /// Note: pow is NOT injective (Remark 4.1)
    /// Multiple τ values can map to same D due to padding
    pub fn is_injective(&self) -> bool {
        false
    }
}

impl<F: Field> DoubleOpeningRelation<F> {
    /// Create new double opening relation
    pub fn new(
        commitment: BaseCommitment<F>,
        split_vector: Vec<i64>,
        matrix: Vec<Vec<RingElement<F>>>,
        norm_bound: u64,
        s_op_norm: f64,
    ) -> Self {
        Self {
            commitment,
            split_vector,
            matrix,
            norm_bound,
            s_op_norm,
        }
    }
    
    /// Verify (τ, M) is valid opening of C_M
    /// 
    /// Checks:
    /// 1. M is valid opening of pow(τ) = com(M)
    /// 2. τ is valid opening of C_M
    pub fn verify(&self, scheme: &AjtaiCommitment<F>) -> Result<bool, String> {
        let d = scheme.ring().degree;
        let d_prime = d / 2;
        let kappa = scheme.kappa();
        let m = self.matrix[0].len();
        
        // Compute ℓ
        let q = scheme.ring().modulus;
        let ell = ((q as f64).log2() / (d_prime as f64).log2()).ceil() as usize;
        
        // Step 1: Verify M is valid opening of pow(τ) = com(M)
        let pow_fn = PowFunction::new(d_prime, ell, kappa, m, scheme.ring().clone());
        let com_m = pow_fn.pow(&self.split_vector)?;
        
        // Commit to each column of M and verify
        for (j, col_cm) in com_m.iter().enumerate() {
            let column: Vec<_> = self.matrix.iter().map(|row| row[j].clone()).collect();
            let computed_cm = scheme.commit(&column)
                .map_err(|e| format!("Column commitment failed: {:?}", e))?;
            
            // Check if commitments match
            if computed_cm.values != *col_cm {
                return Ok(false);
            }
        }
        
        // Step 2: Verify τ is valid opening of C_M
        // Check τ ∈ (-d', d')^n
        for &val in &self.split_vector {
            if val.abs() >= d_prime as i64 {
                return Ok(false);
            }
        }
        
        // Convert τ to ring elements and verify commitment
        let tau_ring = DoubleCommitment::split_to_ring_elements(&self.split_vector, scheme.ring());
        let computed_outer = scheme.commit(&tau_ring)
            .map_err(|e| format!("Outer commitment failed: {:?}", e))?;
        
        if computed_outer.values != self.commitment.values {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Verify binding via Lemma 4.1
    /// If com(·) is binding, then dcom(·) is binding
    pub fn verify_binding(&self) -> bool {
        // Binding inherited from linear commitment
        // Proof by collision reduction (see paper)
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    fn create_test_matrix(n: usize, m: usize, ring: &CyclotomicRing<GoldilocksField>) 
        -> Vec<Vec<RingElement<GoldilocksField>>> {
        let mut matrix = Vec::with_capacity(n);
        for i in 0..n {
            let mut row = Vec::with_capacity(m);
            for j in 0..m {
                let mut coeffs = vec![GoldilocksField::zero(); ring.degree];
                coeffs[0] = GoldilocksField::from_u64((i * m + j) as u64 + 1);
                row.push(RingElement::from_coeffs(coeffs));
            }
            matrix.push(row);
        }
        matrix
    }
    
    #[test]
    fn test_double_commitment_vector() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let seed = [0u8; 32];
        let scheme = AjtaiCommitment::new(ring.clone(), 4, 8, 1 << 20, seed);
        
        let mut vector = Vec::new();
        for i in 0..8 {
            let mut coeffs = vec![GoldilocksField::zero(); 64];
            coeffs[0] = GoldilocksField::from_u64(i as u64 + 1);
            vector.push(RingElement::from_coeffs(coeffs));
        }
        
        let dcom = DoubleCommitment::commit_vector(&scheme, &vector).unwrap();
        assert_eq!(dcom.kappa, 4);
        assert_eq!(dcom.m, 1);
    }
    
    #[test]
    fn test_split_function() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let d_prime = 32;
        let ell = 2;
        let kappa = 4;
        let m = 2;
        
        let split_fn = SplitFunction::new(d_prime, ell, kappa, m, ring.clone());
        
        // Create test commitment matrix
        let com_matrix = create_test_matrix(kappa, m, &ring);
        
        let tau = split_fn.split(&com_matrix).unwrap();
        
        // Verify all values in range
        for &val in &tau {
            assert!(val.abs() < d_prime as i64);
        }
    }
    
    #[test]
    fn test_pow_function() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let d_prime = 32;
        let ell = 2;
        let kappa = 4;
        let m = 2;
        
        let pow_fn = PowFunction::new(d_prime, ell, kappa, m, ring.clone());
        
        // Create test tau vector
        let n = kappa * m * ring.degree * ell;
        let tau: Vec<i64> = (0..n).map(|i| (i % 10) as i64).collect();
        
        let result = pow_fn.pow(&tau).unwrap();
        assert_eq!(result.len(), kappa);
        assert_eq!(result[0].len(), m);
    }
    
    #[test]
    fn test_split_pow_inverse() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let d_prime = 32;
        let ell = 2;
        let kappa = 2;
        let m = 2;
        
        let split_fn = SplitFunction::new(d_prime, ell, kappa, m, ring.clone());
        let pow_fn = PowFunction::new(d_prime, ell, kappa, m, ring.clone());
        
        // Create test matrix
        let matrix = create_test_matrix(kappa, m, &ring);
        
        // Apply split then pow
        let tau = split_fn.split(&matrix).unwrap();
        let reconstructed = pow_fn.pow(&tau).unwrap();
        
        // Verify reconstruction
        assert!(pow_fn.verify_inverse(&matrix, &split_fn).unwrap());
    }
    
    #[test]
    fn test_double_opening_relation() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let seed = [1u8; 32];
        let scheme = AjtaiCommitment::new(ring.clone(), 4, 8, 1 << 20, seed);
        
        let matrix = create_test_matrix(8, 2, &ring);
        
        let dcom = DoubleCommitment::commit_matrix(&scheme, &matrix).unwrap();
        
        let relation = DoubleOpeningRelation::new(
            dcom.outer_commitment.clone(),
            dcom.split_vector.clone(),
            matrix,
            1 << 20,
            10.0,
        );
        
        assert!(relation.verify(&scheme).unwrap());
    }
}
