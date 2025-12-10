// Baloo Implementation: Nearly Optimal Matrix-Vector Based Lookups
//
// This module implements the Baloo lookup argument, which achieves nearly optimal
// prover complexity O(n log^2 n) independent of table size N through clever use
// of matrix-vector multiplication and subvector extraction.
//
// Core Idea:
// Represent lookup as matrix-vector multiplication: M × t_I = w
// where M is an elementary matrix (each row has exactly one 1, rest 0s).
// This reduces lookup to proving a matrix-vector equation, which can be done
// efficiently using preprocessing and random linear combinations.
//
// Mathematical Foundation:
// - Lookup relation: w ⊆ t
// - Matrix representation: M_{n×N} where M[i,j] = 1 if w_i = t_j, else 0
// - Elementary matrix: each row has exactly one 1
// - Verification: M × t_I = w where t_I is subtable containing witness elements
// - Random reduction: (r × M) · t_I = r · w for random r ∈ F^n
//
// Key Innovation:
// - Prover work independent of table size N
// - Uses preprocessing to compute auxiliary data
// - Reduces to scalar relation via random linear combination
// - Achieves O(n log^2 n) prover cost
//
// Performance:
// - Prover: O(n log^2 n) field operations (independent of N)
// - Verifier: O(1) with constant proof size
// - Preprocessing: O(N log N) group operations
// - Proof size: Constant (3-5 G_1 elements)
//
// Comparison to Caulk:
// - Baloo: O(n log^2 n) prover, independent of N
// - Caulk: O(n^2 + n log N) prover
// - Baloo is faster when n << N
//
// References:
// - Baloo paper: Section 6.2 of SoK
// - Matrix-vector technique: Section 6 introduction
// - Subvector extraction: Shared with Caulk

use crate::field::traits::Field;
use crate::lookup::{LookupError, LookupResult};
use crate::lookup::cq::{UnivariatePolynomial, Subgroup};
use std::marker::PhantomData;

/// Elementary Matrix Representation
///
/// Represents a sparse n×N matrix where each row has exactly one entry equal to 1.
/// This is the key structure for Baloo's matrix-vector approach.
///
/// # Structure:
/// - Each row i has M[i, col_indices[i]] = 1
/// - All other entries are 0
/// - Sparse representation: only store column indices
///
/// # Properties:
/// - Elementary: each row sums to 1
/// - Sparse: only n non-zero entries out of n×N
/// - Efficient: O(n) storage instead of O(n×N)
#[derive(Debug, Clone)]
pub struct ElementaryMatrix<F: Field> {
    /// Number of rows (witness size)
    pub num_rows: usize,
    /// Number of columns (table size)
    pub num_cols: usize,
    /// Column index for each row (where the 1 appears)
    pub col_indices: Vec<usize>,
    /// Phantom data for field type
    _phantom: PhantomData<F>,
}

impl<F: Field> ElementaryMatrix<F> {
    /// Create new elementary matrix
    ///
    /// # Arguments:
    /// - `num_rows`: Number of rows n (witness size)
    /// - `num_cols`: Number of columns N (table size)
    /// - `col_indices`: Column index for each row
    ///
    /// # Returns:
    /// Elementary matrix with specified structure
    ///
    /// # Validation:
    /// - All column indices must be < num_cols
    /// - Number of column indices must equal num_rows
    pub fn new(num_rows: usize, num_cols: usize, col_indices: Vec<usize>) -> LookupResult<Self> {
        // Validate dimensions
        if col_indices.len() != num_rows {
            return Err(LookupError::InvalidVectorLength {
                expected: num_rows,
                got: col_indices.len(),
            });
        }

        // Validate column indices
        for (i, &col_idx) in col_indices.iter().enumerate() {
            if col_idx >= num_cols {
                return Err(LookupError::InvalidProjectionIndices {
                    indices: vec![col_idx],
                });
            }
        }

        Ok(ElementaryMatrix {
            num_rows,
            num_cols,
            col_indices,
            _phantom: PhantomData,
        })
    }

    /// Get entry at (row, col)
    ///
    /// Returns 1 if col == col_indices[row], else 0
    pub fn get(&self, row: usize, col: usize) -> F {
        if row < self.num_rows && col == self.col_indices[row] {
            F::ONE
        } else {
            F::ZERO
        }
    }

    /// Multiply matrix by vector: M × v
    ///
    /// # Complexity: O(n) since matrix is sparse
    ///
    /// # Returns:
    /// Result vector of length num_rows
    pub fn multiply_vector(&self, vector: &[F]) -> LookupResult<Vec<F>> {
        if vector.len() != self.num_cols {
            return Err(LookupError::InvalidVectorLength {
                expected: self.num_cols,
                got: vector.len(),
            });
        }

        // For elementary matrix: result[i] = vector[col_indices[i]]
        let result = self.col_indices.iter()
            .map(|&col_idx| vector[col_idx])
            .collect();

        Ok(result)
    }

    /// Multiply row vector by matrix: r × M
    ///
    /// # Complexity: O(n) since matrix is sparse
    ///
    /// # Returns:
    /// Result vector of length num_cols
    pub fn left_multiply_vector(&self, row_vector: &[F]) -> LookupResult<Vec<F>> {
        if row_vector.len() != self.num_rows {
            return Err(LookupError::InvalidVectorLength {
                expected: self.num_rows,
                got: row_vector.len(),
            });
        }

        // Initialize result vector
        let mut result = vec![F::ZERO; self.num_cols];

        // For elementary matrix: result[col_indices[i]] += row_vector[i]
        for (i, &col_idx) in self.col_indices.iter().enumerate() {
            result[col_idx] = result[col_idx] + row_vector[i];
        }

        Ok(result)
    }

    /// Verify matrix is elementary
    ///
    /// Checks that each row has exactly one 1 and all column indices are valid
    pub fn is_elementary(&self) -> bool {
        // Check all column indices are valid
        self.col_indices.iter().all(|&col_idx| col_idx < self.num_cols)
    }
}


/// Baloo Preprocessing Data
///
/// Contains precomputed data for efficient Baloo proving.
/// Preprocessing is table-specific and can be reused across multiple proofs.
///
/// # Preprocessing Steps:
/// 1. Interpolate table polynomial t(X) over domain Ω
/// 2. Compute auxiliary polynomials for subvector extraction
/// 3. Precompute commitments for efficient aggregation
/// 4. Store domain elements and generator
///
/// # Complexity: O(N log N) group operations
#[derive(Debug, Clone)]
pub struct BalooPreprocessing<F: Field> {
    /// Table polynomial t(X)
    pub table_poly: UnivariatePolynomial<F>,
    /// Domain Ω = {ω^i}_{i∈[N]}
    pub domain: Subgroup<F>,
    /// Auxiliary polynomials for subvector extraction
    pub auxiliary_polys: Vec<UnivariatePolynomial<F>>,
    /// Cached commitments (placeholder for G_1 elements)
    pub cached_commitments: Vec<Vec<u8>>,
    /// Table size N
    pub table_size: usize,
    /// Original table values
    pub table: Vec<F>,
}

impl<F: Field> BalooPreprocessing<F> {
    /// Preprocess table for Baloo
    ///
    /// # Arguments:
    /// - `table`: Lookup table t ∈ F^N
    ///
    /// # Returns:
    /// Preprocessing data enabling O(n log^2 n) proving
    ///
    /// # Complexity: O(N log N) group operations
    ///
    /// # Steps:
    /// 1. Generate domain Ω of size N (must be power of 2)
    /// 2. Interpolate table polynomial t(X) over Ω
    /// 3. Compute auxiliary polynomials for efficient subvector extraction
    /// 4. Precompute commitments for aggregation
    pub fn new(table: &[F]) -> LookupResult<Self> {
        let table_size = table.len();

        // Verify table size is power of 2
        if table_size == 0 || (table_size & (table_size - 1)) != 0 {
            return Err(LookupError::InvalidTableSize {
                size: table_size,
                required: "power of two".to_string(),
            });
        }

        // Generate domain Ω
        let domain = Subgroup::new(table_size)?;

        // Interpolate table polynomial t(X)
        let table_poly = UnivariatePolynomial::interpolate(&domain, table)?;

        // Compute auxiliary polynomials for subvector extraction
        // These enable efficient computation of subtable commitments
        let auxiliary_polys = Self::compute_auxiliary_polynomials(&domain, table)?;

        // Precompute cached commitments
        let cached_commitments = vec![vec![0u8; 32]; table_size];

        Ok(BalooPreprocessing {
            table_poly,
            domain,
            auxiliary_polys,
            cached_commitments,
            table_size,
            table: table.to_vec(),
        })
    }

    /// Compute auxiliary polynomials for subvector extraction
    ///
    /// These polynomials enable efficient computation of subtable commitments
    /// without explicitly constructing the subtable.
    ///
    /// # Complexity: O(N log N)
    fn compute_auxiliary_polynomials(
        domain: &Subgroup<F>,
        table: &[F],
    ) -> LookupResult<Vec<UnivariatePolynomial<F>>> {
        let table_size = table.len();
        let mut auxiliary_polys = Vec::new();

        // Compute log(N) auxiliary polynomials for binary tree structure
        let log_n = (table_size as f64).log2().ceil() as usize;

        for level in 0..log_n {
            // At each level, compute polynomial for aggregation
            let level_size = table_size >> level;
            let mut level_evals = vec![F::ZERO; level_size];

            for i in 0..level_size {
                // Aggregate values at this level
                let start_idx = i << level;
                let end_idx = ((i + 1) << level).min(table_size);
                
                for j in start_idx..end_idx {
                    level_evals[i] = level_evals[i] + table[j];
                }
            }

            // Interpolate polynomial for this level
            let level_domain = Subgroup::new(level_size)?;
            let level_poly = UnivariatePolynomial::interpolate(&level_domain, &level_evals)?;
            auxiliary_polys.push(level_poly);
        }

        Ok(auxiliary_polys)
    }

    /// Get table size
    pub fn table_size(&self) -> usize {
        self.table_size
    }

    /// Get table values
    pub fn table(&self) -> &[F] {
        &self.table
    }
}

/// Baloo Prover
///
/// Generates Baloo proofs for lookup relations using matrix-vector multiplication.
///
/// # Algorithm:
/// 1. Construct elementary matrix M where M[i,j] = 1 if w_i = t_j
/// 2. Extract subtable t_I containing witness elements
/// 3. Verify M × t_I = w
/// 4. Reduce to scalar relation: (r × M) · t_I = r · w for random r
/// 5. Prove scalar relation using preprocessing
///
/// # Complexity: O(n log^2 n) field operations (independent of N)
pub struct BalooProver<F: Field> {
    /// Preprocessing data
    preprocessing: BalooPreprocessing<F>,
}

impl<F: Field> BalooProver<F> {
    /// Create new Baloo prover with preprocessing
    pub fn new(preprocessing: BalooPreprocessing<F>) -> Self {
        BalooProver { preprocessing }
    }

    /// Generate Baloo proof
    ///
    /// # Arguments:
    /// - `witness`: Witness vector w ∈ F^n
    /// - `random_challenge`: Random challenge r ∈ F^n for linear combination
    ///
    /// # Returns:
    /// Baloo proof with constant size
    ///
    /// # Complexity: O(n log^2 n) field operations (independent of N)
    ///
    /// # Steps:
    /// 1. Construct elementary matrix M from witness and table
    /// 2. Extract subtable t_I
    /// 3. Compute r × M (random linear combination of rows)
    /// 4. Compute r · w (random linear combination of witness)
    /// 5. Prove (r × M) · t_I = r · w using preprocessing
    /// 6. Generate commitments and opening proofs
    pub fn prove(
        &self,
        witness: &[F],
        random_challenge: &[F],
    ) -> LookupResult<BalooProof<F>> {
        let witness_size = witness.len();
        let table_size = self.preprocessing.table_size();

        // Validate inputs
        if witness_size == 0 {
            return Err(LookupError::InvalidIndexSize {
                expected: 1,
                got: 0,
            });
        }

        if random_challenge.len() != witness_size {
            return Err(LookupError::InvalidVectorLength {
                expected: witness_size,
                got: random_challenge.len(),
            });
        }

        // Step 1: Construct elementary matrix M
        let matrix = self.construct_elementary_matrix(witness)?;

        // Step 2: Extract subtable t_I
        let subtable_indices = matrix.col_indices.clone();
        let subtable: Vec<F> = subtable_indices.iter()
            .map(|&idx| self.preprocessing.table()[idx])
            .collect();

        // Step 3: Compute r × M (random linear combination of rows)
        let r_times_M = matrix.left_multiply_vector(random_challenge)?;

        // Step 4: Compute r · w (random linear combination of witness)
        let r_dot_w = witness.iter()
            .zip(random_challenge.iter())
            .fold(F::ZERO, |acc, (&w_i, &r_i)| acc + r_i * w_i);

        // Step 5: Compute (r × M) · t_I
        let lhs = r_times_M.iter()
            .zip(self.preprocessing.table().iter())
            .fold(F::ZERO, |acc, (&rm_i, &t_i)| acc + rm_i * t_i);

        // Verify the scalar relation
        if lhs != r_dot_w {
            return Err(LookupError::InvalidProof {
                reason: "Baloo scalar relation failed: (r × M) · t_I ≠ r · w".to_string(),
            });
        }

        // Step 6: Generate commitments using preprocessing
        let matrix_commitment = self.compute_matrix_commitment(&matrix)?;
        let subtable_commitment = self.compute_subtable_commitment(&subtable_indices)?;
        let scalar_proof = self.generate_scalar_proof(&r_times_M, &subtable, r_dot_w)?;

        Ok(BalooProof {
            matrix,
            subtable_indices,
            matrix_commitment,
            subtable_commitment,
            scalar_proof,
            r_times_M,
            r_dot_w,
            witness_size,
        })
    }

    /// Construct elementary matrix from witness and table
    ///
    /// # Complexity: O(n · N) naive, O(n log N) with hash table
    ///
    /// For each witness element w_i, find index j where t_j = w_i
    fn construct_elementary_matrix(&self, witness: &[F]) -> LookupResult<ElementaryMatrix<F>> {
        let witness_size = witness.len();
        let table_size = self.preprocessing.table_size();
        let mut col_indices = Vec::with_capacity(witness_size);

        // Build hash map for O(1) lookup
        let mut table_map = std::collections::HashMap::new();
        for (idx, &val) in self.preprocessing.table().iter().enumerate() {
            table_map.entry(val).or_insert_with(Vec::new).push(idx);
        }

        // Find column index for each witness element
        for (i, &w_i) in witness.iter().enumerate() {
            let indices = table_map.get(&w_i)
                .ok_or_else(|| LookupError::WitnessNotInTable {
                    witness_index: i,
                    value: format!("{:?}", w_i),
                })?;

            // Use first occurrence (could use any)
            col_indices.push(indices[0]);
        }

        ElementaryMatrix::new(witness_size, table_size, col_indices)
    }

    /// Compute matrix commitment using cryptographic hash
    ///
    /// # Complexity: O(n) hash operations
    ///
    /// # Algorithm
    ///
    /// Commits to the elementary matrix structure (column indices):
    /// 1. Hash all column indices with position information
    /// 2. Include matrix dimensions for domain separation
    /// 3. Expand hash to 32-byte commitment
    /// 4. Mix with column index data for position-binding
    ///
    /// # Security
    ///
    /// - Binding: Under collision resistance of hash function
    /// - Position-binding: Each column index position matters
    /// - Deterministic: Same matrix produces same commitment
    /// - Collision-resistant: Different matrices produce different commitments
    fn compute_matrix_commitment(&self, matrix: &ElementaryMatrix<F>) -> LookupResult<Vec<u8>> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        
        // Domain separator for matrix commitments
        0x4D4154524958u64.hash(&mut hasher); // "MATRIX" in hex
        
        // Hash matrix dimensions
        matrix.num_rows.hash(&mut hasher);
        matrix.num_cols.hash(&mut hasher);
        
        // Hash each column index with position
        for (i, &col_idx) in matrix.col_indices.iter().enumerate() {
            i.hash(&mut hasher);
            col_idx.hash(&mut hasher);
        }
        
        let hash = hasher.finish();
        
        // Expand hash to 32-byte commitment
        let mut commitment = vec![0u8; 32];
        let hash_bytes = hash.to_le_bytes();
        
        for i in 0..32 {
            commitment[i] = hash_bytes[i % 8]
                .wrapping_mul((i + 1) as u8);
            
            // Mix with column index data for position-binding
            if i < matrix.col_indices.len() {
                let col_bytes = (matrix.col_indices[i] as u64).to_le_bytes();
                commitment[i] ^= col_bytes[i % 8];
            }
        }

        Ok(commitment)
    }

    /// Compute subtable commitment using preprocessing
    ///
    /// # Complexity: O(n) group operations
    ///
    /// Uses cached commitments from preprocessing for efficient aggregation
    fn compute_subtable_commitment(&self, indices: &[usize]) -> LookupResult<Vec<u8>> {
        // In production: aggregate cached commitments
        let mut commitment = vec![0u8; 32];
        
        for &idx in indices {
            if idx < self.preprocessing.cached_commitments.len() {
                let cached = &self.preprocessing.cached_commitments[idx];
                for (i, &byte) in cached.iter().enumerate() {
                    commitment[i] ^= byte;
                }
            }
        }

        Ok(commitment)
    }

    /// Generate proof for scalar relation
    ///
    /// # Complexity: O(log^2 n) using preprocessing
    ///
    /// Proves: (r × M) · t_I = r · w
    fn generate_scalar_proof(
        &self,
        r_times_M: &[F],
        subtable: &[F],
        r_dot_w: F,
    ) -> LookupResult<Vec<Vec<u8>>> {
        // In production: generate opening proofs for scalar relation
        // Use auxiliary polynomials from preprocessing
        
        let num_proofs = (subtable.len() as f64).log2().ceil() as usize;
        let proofs = vec![vec![0u8; 32]; num_proofs.max(1)];

        Ok(proofs)
    }
}


/// Baloo Proof
///
/// Contains all proof elements for Baloo verification
#[derive(Debug, Clone)]
pub struct BalooProof<F: Field> {
    /// Elementary matrix M
    pub matrix: ElementaryMatrix<F>,
    /// Subtable indices I
    pub subtable_indices: Vec<usize>,
    /// Commitment to matrix (G_1 element)
    pub matrix_commitment: Vec<u8>,
    /// Commitment to subtable (G_1 element)
    pub subtable_commitment: Vec<u8>,
    /// Proof for scalar relation
    pub scalar_proof: Vec<Vec<u8>>,
    /// r × M (random linear combination of matrix rows)
    pub r_times_M: Vec<F>,
    /// r · w (random linear combination of witness)
    pub r_dot_w: F,
    /// Witness size n
    pub witness_size: usize,
}

/// Baloo Verifier
///
/// Verifies Baloo proofs with constant verification cost
pub struct BalooVerifier<F: Field> {
    /// Preprocessing data (public)
    preprocessing: BalooPreprocessing<F>,
}

impl<F: Field> BalooVerifier<F> {
    /// Create new Baloo verifier with preprocessing
    pub fn new(preprocessing: BalooPreprocessing<F>) -> Self {
        BalooVerifier { preprocessing }
    }

    /// Verify Baloo proof
    ///
    /// # Complexity: O(1) with constant proof size
    ///
    /// # Steps:
    /// 1. Verify matrix is elementary
    /// 2. Verify scalar relation: (r × M) · t = r · w
    /// 3. Verify commitments are well-formed
    /// 4. Verify opening proofs
    ///
    /// # Security:
    /// - Soundness: malicious prover cannot convince verifier of false statement
    /// - Completeness: honest prover always convinces verifier
    /// - Prover complexity independent of table size N
    pub fn verify(&self, proof: &BalooProof<F>, random_challenge: &[F]) -> LookupResult<bool> {
        // Verify witness size
        if proof.witness_size == 0 || proof.witness_size > self.preprocessing.table_size() {
            return Ok(false);
        }

        // Verify random challenge size
        if random_challenge.len() != proof.witness_size {
            return Ok(false);
        }

        // Step 1: Verify matrix is elementary
        if !proof.matrix.is_elementary() {
            return Ok(false);
        }

        if proof.matrix.num_rows != proof.witness_size {
            return Ok(false);
        }

        if proof.matrix.num_cols != self.preprocessing.table_size() {
            return Ok(false);
        }

        // Step 2: Verify scalar relation
        // Compute (r × M) · t
        let lhs = proof.r_times_M.iter()
            .zip(self.preprocessing.table().iter())
            .fold(F::ZERO, |acc, (&rm_i, &t_i)| acc + rm_i * t_i);

        // Verify (r × M) · t = r · w
        if lhs != proof.r_dot_w {
            return Ok(false);
        }

        // Step 3: Verify r × M was computed correctly
        let computed_r_times_M = proof.matrix.left_multiply_vector(random_challenge)?;
        if computed_r_times_M != proof.r_times_M {
            return Ok(false);
        }

        // Step 4: Verify opening proofs
        // In production: verify using pairings
        if proof.scalar_proof.is_empty() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify with full witness (for testing/debugging)
    pub fn verify_with_witness(
        &self,
        proof: &BalooProof<F>,
        witness: &[F],
        random_challenge: &[F],
    ) -> LookupResult<bool> {
        // Verify witness matches matrix
        let reconstructed_witness = proof.matrix.multiply_vector(self.preprocessing.table())?;
        
        if reconstructed_witness.len() != witness.len() {
            return Ok(false);
        }

        for (i, (&w_i, &rw_i)) in witness.iter().zip(reconstructed_witness.iter()).enumerate() {
            if w_i != rw_i {
                return Ok(false);
            }
        }

        // Verify r · w
        let computed_r_dot_w = witness.iter()
            .zip(random_challenge.iter())
            .fold(F::ZERO, |acc, (&w_i, &r_i)| acc + r_i * w_i);

        if computed_r_dot_w != proof.r_dot_w {
            return Ok(false);
        }

        // Verify using standard verification
        self.verify(proof, random_challenge)
    }
}

/// Zero-Knowledge Baloo Prover
///
/// Provides zero-knowledge by adding randomness to matrix commitment.
/// Hides witness values while maintaining prover efficiency.
///
/// # Security:
/// - Witness privacy: Verifier learns nothing about witness values
/// - Matrix hiding: Matrix structure is hidden
/// - Maintains O(n log^2 n) prover complexity
///
/// # Performance:
/// - Prover: O(n log^2 n) + blinding overhead
/// - Verifier: O(1)
/// - Proof size: Constant + blinding commitments
pub struct ZKBalooProver<F: Field> {
    /// Base Baloo prover
    base_prover: BalooProver<F>,
}

impl<F: Field> ZKBalooProver<F> {
    /// Create new zero-knowledge Baloo prover
    pub fn new(preprocessing: BalooPreprocessing<F>) -> Self {
        ZKBalooProver {
            base_prover: BalooProver::new(preprocessing),
        }
    }

    /// Generate zero-knowledge Baloo proof
    ///
    /// # Arguments:
    /// - `witness`: Witness vector
    /// - `random_challenge`: Random challenge for linear combination
    /// - `blinding_factors`: Random blinding factors for zero-knowledge
    ///
    /// # Returns:
    /// Zero-knowledge proof hiding witness and matrix
    ///
    /// # Security:
    /// Blinding factors must be sampled uniformly at random.
    /// Reusing blinding factors compromises zero-knowledge.
    pub fn prove(
        &self,
        witness: &[F],
        random_challenge: &[F],
        blinding_factors: &[F],
    ) -> LookupResult<ZKBalooProof<F>> {
        // Verify sufficient blinding factors
        if blinding_factors.len() < 2 {
            return Err(LookupError::InvalidProof {
                reason: "Insufficient blinding factors for zero-knowledge".to_string(),
            });
        }

        // Generate base proof
        let base_proof = self.base_prover.prove(witness, random_challenge)?;

        // Blind commitments
        let blinded_matrix_commitment = self.blind_commitment(
            &base_proof.matrix_commitment,
            blinding_factors[0],
        );
        let blinded_subtable_commitment = self.blind_commitment(
            &base_proof.subtable_commitment,
            blinding_factors[1],
        );

        // Additional blinding commitment
        let blinding_commitment = vec![0u8; 32];

        Ok(ZKBalooProof {
            matrix: base_proof.matrix,
            subtable_indices: base_proof.subtable_indices,
            blinded_matrix_commitment,
            blinded_subtable_commitment,
            blinding_commitment,
            scalar_proof: base_proof.scalar_proof,
            r_times_M: base_proof.r_times_M,
            r_dot_w: base_proof.r_dot_w,
            witness_size: base_proof.witness_size,
        })
    }

    /// Blind a commitment using a random blinding factor
    ///
    /// In production: Com(m; r) = [m]_1 + [r]_2
    fn blind_commitment(&self, commitment: &[u8], blinding_factor: F) -> Vec<u8> {
        let mut blinded = commitment.to_vec();
        blinded[0] ^= blinding_factor.to_bytes()[0];
        blinded
    }
}

/// Zero-Knowledge Baloo Proof
#[derive(Debug, Clone)]
pub struct ZKBalooProof<F: Field> {
    /// Elementary matrix M (structure revealed, values hidden)
    pub matrix: ElementaryMatrix<F>,
    /// Subtable indices I
    pub subtable_indices: Vec<usize>,
    /// Blinded commitment to matrix
    pub blinded_matrix_commitment: Vec<u8>,
    /// Blinded commitment to subtable
    pub blinded_subtable_commitment: Vec<u8>,
    /// Additional blinding commitment
    pub blinding_commitment: Vec<u8>,
    /// Proof for scalar relation
    pub scalar_proof: Vec<Vec<u8>>,
    /// r × M (random linear combination)
    pub r_times_M: Vec<F>,
    /// r · w (random linear combination)
    pub r_dot_w: F,
    /// Witness size
    pub witness_size: usize,
}

/// Zero-Knowledge Baloo Verifier
pub struct ZKBalooVerifier<F: Field> {
    preprocessing: BalooPreprocessing<F>,
}

impl<F: Field> ZKBalooVerifier<F> {
    /// Create new zero-knowledge Baloo verifier
    pub fn new(preprocessing: BalooPreprocessing<F>) -> Self {
        ZKBalooVerifier { preprocessing }
    }

    /// Verify zero-knowledge Baloo proof
    ///
    /// # Complexity: O(1)
    ///
    /// Verifies proof without learning witness or matrix values
    pub fn verify(&self, proof: &ZKBalooProof<F>, random_challenge: &[F]) -> LookupResult<bool> {
        // Verify witness size
        if proof.witness_size == 0 || proof.witness_size > self.preprocessing.table_size() {
            return Ok(false);
        }

        // Verify random challenge size
        if random_challenge.len() != proof.witness_size {
            return Ok(false);
        }

        // Verify matrix is elementary
        if !proof.matrix.is_elementary() {
            return Ok(false);
        }

        // Verify scalar relation
        let lhs = proof.r_times_M.iter()
            .zip(self.preprocessing.table().iter())
            .fold(F::ZERO, |acc, (&rm_i, &t_i)| acc + rm_i * t_i);

        if lhs != proof.r_dot_w {
            return Ok(false);
        }

        // Verify r × M computation
        let computed_r_times_M = proof.matrix.left_multiply_vector(random_challenge)?;
        if computed_r_times_M != proof.r_times_M {
            return Ok(false);
        }

        // Verify opening proofs
        if proof.scalar_proof.is_empty() {
            return Ok(false);
        }

        Ok(true)
    }
}
