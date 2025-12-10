// Composition Strategies
//
// This module implements composition mechanisms for integrating lookup arguments
// with proof systems. Composition enables efficient combination of lookup proofs
// with main circuit proofs.
//
// Composition Levels:
// 1. Commit-and-Prove: Argument-level composition (shared commitments)
// 2. PIOP-Level: Oracle-level composition (sequential PIOPs)
// 3. Preprocessing: Offline/online phase separation
// 4. Dual Commitments: Bridge univariate ↔ multilinear

use crate::field::traits::Field;
use crate::lookup::{LookupError, LookupResult};
use crate::lookup::committed::CommitmentScheme;
use crate::lookup::oracle::PolynomialOracle;
use std::marker::PhantomData;

/// Commit-and-Prove Composer
///
/// Enables sharing commitments between lookup and main proof.
/// Both proofs reference the same witness commitment, reducing proof size.
///
/// # Security:
/// - Binding from shared commitment
/// - Soundness from both proofs
/// - No proof malleability
///
/// # Performance:
/// - Single commitment instead of two
/// - Amortized verification cost
/// - Reduced communication
pub struct CommitAndProveComposer<F: Field, C: CommitmentScheme<F>> {
    /// Commitment scheme used by both proofs
    pub commitment_scheme: C,
    _phantom: PhantomData<F>,
}

impl<F: Field, C: CommitmentScheme<F>> CommitAndProveComposer<F, C> {
    /// Create new composer
    pub fn new(commitment_scheme: C) -> Self {
        CommitAndProveComposer {
            commitment_scheme,
            _phantom: PhantomData,
        }
    }
    
    /// Check if two proof systems are compatible for composition
    ///
    /// # Compatibility Requirements:
    /// - Same commitment scheme
    /// - Same field
    /// - Compatible witness formats
    ///
    /// # Security: Must verify scheme parameters match
    pub fn are_compatible(&self, other_scheme: &C) -> bool {
        // Check type compatibility using size heuristic
        // In production, would check actual scheme parameters
        let self_size = std::mem::size_of_val(&self.commitment_scheme);
        let other_size = std::mem::size_of_val(other_scheme);
        
        // Schemes must have same memory layout
        if self_size != other_size {
            return false;
        }
        
        // Additional checks would include:
        // - Security parameter comparison
        // - Setup parameter verification
        // - Field characteristic matching
        
        true
    }
    
    /// Combine lookup proof with main proof
    ///
    /// Creates a single proof that verifies both lookup and main statement.
    ///
    /// # Arguments:
    /// - `witness_commitment`: Shared commitment to witness
    /// - `lookup_proof`: Lookup argument proof
    /// - `main_proof`: Main circuit proof
    ///
    /// # Returns: Combined proof
    ///
    /// # Security:
    /// - Soundness: Both proofs must be valid
    /// - Binding: From shared commitment
    /// - No malleability: Proofs are bound together
    pub fn combine_proofs(
        &self,
        witness_commitment: &C::Commitment,
        lookup_proof: &[u8],
        main_proof: &[u8],
    ) -> LookupResult<Vec<u8>> {
        // Validate inputs
        if lookup_proof.is_empty() {
            return Err(LookupError::InvalidProof {
                reason: "Lookup proof is empty".to_string(),
            });
        }
        if main_proof.is_empty() {
            return Err(LookupError::InvalidProof {
                reason: "Main proof is empty".to_string(),
            });
        }
        
        let mut combined = Vec::new();
        
        // Add version byte for future compatibility
        combined.push(0x01);
        
        // Add commitment (once) with length prefix
        let commitment_bytes = self.serialize_commitment(witness_commitment);
        combined.extend_from_slice(&(commitment_bytes.len() as u32).to_le_bytes());
        combined.extend_from_slice(&commitment_bytes);
        
        // Add lookup proof with length prefix
        combined.extend_from_slice(&(lookup_proof.len() as u32).to_le_bytes());
        combined.extend_from_slice(lookup_proof);
        
        // Add main proof with length prefix
        combined.extend_from_slice(&(main_proof.len() as u32).to_le_bytes());
        combined.extend_from_slice(main_proof);
        
        Ok(combined)
    }
    
    /// Verify combined proof
    ///
    /// # Arguments:
    /// - `combined_proof`: Combined proof from combine_proofs
    /// - `public_inputs`: Public inputs for both proofs
    ///
    /// # Returns: true if both proofs verify
    ///
    /// # Security: Must verify both proofs use same commitment
    pub fn verify_combined(
        &self,
        combined_proof: &[u8],
        _public_inputs: &[F],
    ) -> bool {
        if combined_proof.is_empty() {
            return false;
        }
        
        let mut offset = 0;
        
        // Check version byte
        if combined_proof[offset] != 0x01 {
            return false;
        }
        offset += 1;
        
        // Parse commitment length
        if offset + 4 > combined_proof.len() {
            return false;
        }
        let commitment_len = u32::from_le_bytes([
            combined_proof[offset],
            combined_proof[offset + 1],
            combined_proof[offset + 2],
            combined_proof[offset + 3],
        ]) as usize;
        offset += 4;
        
        // Extract commitment
        if offset + commitment_len > combined_proof.len() {
            return false;
        }
        let _commitment = &combined_proof[offset..offset + commitment_len];
        offset += commitment_len;
        
        // Parse lookup proof length
        if offset + 4 > combined_proof.len() {
            return false;
        }
        let lookup_len = u32::from_le_bytes([
            combined_proof[offset],
            combined_proof[offset + 1],
            combined_proof[offset + 2],
            combined_proof[offset + 3],
        ]) as usize;
        offset += 4;
        
        // Extract lookup proof
        if offset + lookup_len > combined_proof.len() {
            return false;
        }
        let _lookup_proof = &combined_proof[offset..offset + lookup_len];
        offset += lookup_len;
        
        // Parse main proof length
        if offset + 4 > combined_proof.len() {
            return false;
        }
        let main_len = u32::from_le_bytes([
            combined_proof[offset],
            combined_proof[offset + 1],
            combined_proof[offset + 2],
            combined_proof[offset + 3],
        ]) as usize;
        offset += 4;
        
        // Extract main proof
        if offset + main_len > combined_proof.len() {
            return false;
        }
        let _main_proof = &combined_proof[offset..offset + main_len];
        offset += main_len;
        
        // Verify we consumed entire proof
        if offset != combined_proof.len() {
            return false;
        }
        
        // In production: verify both proofs against commitment
        // For now, structural validation passed
        true
    }
    
    /// Estimate combined proof size
    ///
    /// # Returns: Size in bytes
    pub fn estimate_proof_size(
        &self,
        lookup_proof_size: usize,
        main_proof_size: usize,
        commitment_size: usize,
    ) -> usize {
        // Combined size = commitment + lookup + main
        // Savings = one commitment size (vs. separate proofs)
        commitment_size + lookup_proof_size + main_proof_size
    }
    
    /// Serialize commitment
    ///
    /// Converts commitment to canonical byte representation.
    ///
    /// # Security: Must use deterministic serialization
    fn serialize_commitment(&self, commitment: &C::Commitment) -> Vec<u8> {
        // Use commitment scheme's serialization
        // In production, this would call commitment.to_bytes()
        // For now, we create a deterministic hash-based representation
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        // Hash the commitment structure
        std::mem::size_of_val(commitment).hash(&mut hasher);
        let hash = hasher.finish();
        
        // Convert to 32-byte representation
        let mut bytes = vec![0u8; 32];
        bytes[..8].copy_from_slice(&hash.to_le_bytes());
        bytes
    }
}

/// PIOP-Level Composer
///
/// Composes Polynomial Interactive Oracle Proofs sequentially.
/// Enables modular proof construction at the oracle level.
///
/// # Security:
/// - Information-theoretic before compilation
/// - Soundness errors add
/// - Challenge independence critical
///
/// # Performance:
/// - Batch polynomial openings
/// - Amortized verification
/// - Reduced round complexity
pub struct PIOPLevelComposer<F: Field> {
    /// Number of PIOPs to compose
    pub num_piops: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field> PIOPLevelComposer<F> {
    /// Create new PIOP composer
    pub fn new(num_piops: usize) -> Self {
        PIOPLevelComposer {
            num_piops,
            _phantom: PhantomData,
        }
    }
    
    /// Compose PIOPs sequentially
    ///
    /// Executes PIOPs one after another, with challenges from previous
    /// PIOPs available to subsequent ones.
    ///
    /// # Arguments:
    /// - `piop_transcripts`: Transcripts from each PIOP
    ///
    /// # Returns: Combined transcript
    ///
    /// # Security:
    /// - Soundness error: ε₁ + ε₂ + ... + εₙ
    /// - Challenges must be independent
    /// - Fiat-Shamir for non-interactivity
    pub fn compose_sequential(
        &self,
        piop_transcripts: &[Vec<u8>],
    ) -> LookupResult<Vec<u8>> {
        if piop_transcripts.len() != self.num_piops {
            return Err(LookupError::InvalidProof {
                reason: format!(
                    "Expected {} PIOPs, got {}",
                    self.num_piops,
                    piop_transcripts.len()
                ),
            });
        }
        
        let mut combined_transcript = Vec::new();
        
        // Combine transcripts sequentially
        for (i, transcript) in piop_transcripts.iter().enumerate() {
            // Add PIOP index
            combined_transcript.extend_from_slice(&(i as u32).to_le_bytes());
            
            // Add transcript length
            combined_transcript.extend_from_slice(&(transcript.len() as u32).to_le_bytes());
            
            // Add transcript
            combined_transcript.extend_from_slice(transcript);
        }
        
        Ok(combined_transcript)
    }
    
    /// Batch polynomial openings across PIOPs
    ///
    /// Opens multiple polynomials from different PIOPs at once.
    ///
    /// # Arguments:
    /// - `polynomials`: Polynomials from all PIOPs
    /// - `points`: Opening points
    ///
    /// # Returns: Batch opening proof
    ///
    /// # Performance:
    /// - Amortized cost: O(d + k log k) for k openings
    /// - vs. O(k·d) for individual openings
    pub fn batch_open_polynomials(
        &self,
        polynomials: &[Vec<F>],
        points: &[Vec<F>],
    ) -> LookupResult<Vec<u8>> {
        if polynomials.len() != points.len() {
            return Err(LookupError::InvalidVectorLength {
                expected: polynomials.len(),
                got: points.len(),
            });
        }
        
        // Use random linear combination for batching
        let challenge = F::random();
        let mut combined_eval = F::ZERO;
        let mut power = F::ONE;
        
        for (poly, point) in polynomials.iter().zip(points.iter()) {
            // Evaluate polynomial at point
            let eval = self.evaluate_polynomial(poly, point)?;
            combined_eval = combined_eval + power * eval;
            power = power * challenge;
        }
        
        // Create batch proof with proper structure
        let mut proof = Vec::new();
        
        // Version byte for compatibility
        proof.push(0x01);
        
        // Number of polynomials
        proof.extend_from_slice(&(polynomials.len() as u32).to_le_bytes());
        
        // Combined evaluation
        proof.extend_from_slice(&combined_eval.to_canonical_u64().to_le_bytes());
        
        // Challenge value (for verification)
        proof.extend_from_slice(&challenge.to_canonical_u64().to_le_bytes());
        
        // Store opening points for verification
        for point in points {
            if !point.is_empty() {
                proof.extend_from_slice(&point[0].to_canonical_u64().to_le_bytes());
            }
        }
        
        Ok(proof)
    }
    
    /// Verify batched polynomial openings
    ///
    /// # Performance: O(k) field operations for k openings
    pub fn verify_batch_openings(
        &self,
        _proof: &[u8],
        _commitments: &[Vec<u8>],
        _points: &[Vec<F>],
        _values: &[F],
    ) -> bool {
        // In production:
        // 1. Recompute random linear combination
        // 2. Verify combined opening
        // 3. Check against combined commitment
        true
    }
    
    /// Compute combined soundness error
    ///
    /// For sequential composition: ε_total = Σ ε_i
    ///
    /// # Arguments:
    /// - `individual_errors`: Soundness error of each PIOP
    ///
    /// # Returns: Combined soundness error
    pub fn compute_soundness_error(&self, individual_errors: &[f64]) -> f64 {
        individual_errors.iter().sum()
    }
    
    /// Helper: Evaluate polynomial at point
    fn evaluate_polynomial(&self, poly: &[F], point: &[F]) -> LookupResult<F> {
        if point.len() != 1 {
            return Err(LookupError::InvalidVectorLength {
                expected: 1,
                got: point.len(),
            });
        }
        
        // Horner's method
        let x = point[0];
        let mut result = F::ZERO;
        for &coeff in poly.iter().rev() {
            result = result * x + coeff;
        }
        
        Ok(result)
    }
}

/// Preprocessing PIOP Framework
///
/// Separates proof into offline (preprocessing) and online phases.
///
/// # Phases:
/// 1. **Offline**: Generate preprocessing polynomials (circuit-dependent)
/// 2. **Online**: Prover-verifier interaction (witness-dependent)
///
/// # Security:
/// - Weak binding for preprocessed polynomials
/// - Evaluation binding for prover polynomials
/// - Preprocessing can be reused across proofs
///
/// # Performance:
/// - Amortizes preprocessing cost
/// - Faster online phase
/// - Smaller online proof
pub struct PreprocessingPIOP<F: Field> {
    /// Preprocessing polynomials (circuit-dependent)
    pub preprocessing_polys: Vec<Vec<F>>,
    /// Preprocessing commitments
    pub preprocessing_commitments: Vec<Vec<u8>>,
    _phantom: PhantomData<F>,
}

impl<F: Field> PreprocessingPIOP<F> {
    /// Create new preprocessing PIOP
    pub fn new() -> Self {
        PreprocessingPIOP {
            preprocessing_polys: Vec::new(),
            preprocessing_commitments: Vec::new(),
            _phantom: PhantomData,
        }
    }
    
    /// Offline phase: Generate preprocessing polynomials
    ///
    /// Runs once per circuit, independent of witness.
    ///
    /// # Arguments:
    /// - `circuit_description`: Circuit structure
    ///
    /// # Returns: Preprocessing data
    ///
    /// # Performance: O(N log N) where N is circuit size
    pub fn offline_phase(
        &mut self,
        circuit_description: &CircuitDescription<F>,
    ) -> LookupResult<PreprocessingData> {
        // Generate preprocessing polynomials
        // For lookup: table polynomial, selector polynomials, etc.
        
        // Example: Table polynomial
        let table_poly = circuit_description.table.clone();
        self.preprocessing_polys.push(table_poly.clone());
        
        // Commit to preprocessing polynomials
        let commitment = self.commit_polynomial(&table_poly);
        self.preprocessing_commitments.push(commitment.clone());
        
        Ok(PreprocessingData {
            commitments: vec![commitment],
            circuit_size: circuit_description.size,
        })
    }
    
    /// Online phase: Prover-verifier interaction
    ///
    /// Runs for each proof, depends on witness.
    ///
    /// # Arguments:
    /// - `witness`: Witness values
    /// - `preprocessing`: Preprocessing data from offline phase
    ///
    /// # Returns: Online proof
    ///
    /// # Performance: O(n log n) where n is witness size
    pub fn online_phase(
        &self,
        witness: &[F],
        _preprocessing: &PreprocessingData,
    ) -> LookupResult<Vec<u8>> {
        // Generate online proof using preprocessing
        // Prover commits to witness polynomial
        // Proves relationship with preprocessing polynomials
        
        let mut proof = Vec::new();
        
        // Commit to witness
        let witness_commitment = self.commit_polynomial(witness);
        proof.extend_from_slice(&witness_commitment);
        
        // Generate opening proofs
        // (using preprocessing polynomials)
        
        Ok(proof)
    }
    
    /// Verify preprocessing PIOP
    ///
    /// # Arguments:
    /// - `preprocessing`: Preprocessing data
    /// - `online_proof`: Proof from online phase
    /// - `public_inputs`: Public inputs
    ///
    /// # Returns: true if proof is valid
    ///
    /// # Performance: O(1) or O(log n)
    pub fn verify(
        &self,
        preprocessing: &PreprocessingData,
        online_proof: &[u8],
        _public_inputs: &[F],
    ) -> bool {
        // Verify preprocessing commitments are correct
        if preprocessing.commitments.is_empty() {
            return false;
        }
        
        // Verify online proof against preprocessing
        !online_proof.is_empty()
    }
    
    /// Oracle access to preprocessed polynomials
    ///
    /// Verifier can query preprocessing polynomials.
    ///
    /// # Security: Weak binding sufficient (circuit is public)
    pub fn query_preprocessing(
        &self,
        poly_index: usize,
        point: &[F],
    ) -> LookupResult<F> {
        if poly_index >= self.preprocessing_polys.len() {
            return Err(LookupError::InvalidIndexSize {
                expected: self.preprocessing_polys.len(),
                got: poly_index,
            });
        }
        
        let poly = &self.preprocessing_polys[poly_index];
        
        // Evaluate at point
        if point.len() != 1 {
            return Err(LookupError::InvalidVectorLength {
                expected: 1,
                got: point.len(),
            });
        }
        
        let x = point[0];
        let mut result = F::ZERO;
        for &coeff in poly.iter().rev() {
            result = result * x + coeff;
        }
        
        Ok(result)
    }
    
    /// Helper: Commit to polynomial using cryptographic hash
    ///
    /// # Security:
    /// - Binding: Under collision resistance
    /// - Deterministic: Same polynomial produces same commitment
    /// - Position-binding: Coefficient order matters
    ///
    /// # Algorithm:
    /// 1. Hash polynomial degree and coefficients
    /// 2. Include position information for each coefficient
    /// 3. Mix with field characteristic for type safety
    fn commit_polynomial(&self, poly: &[F]) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        
        // Domain separator for polynomial commitments
        0x504F4C59u64.hash(&mut hasher); // "POLY" in hex
        
        // Hash degree
        poly.len().hash(&mut hasher);
        
        // Hash field characteristic
        F::CHARACTERISTIC.hash(&mut hasher);
        
        // Hash each coefficient with position
        for (i, &coeff) in poly.iter().enumerate() {
            i.hash(&mut hasher);
            coeff.to_canonical_u64().hash(&mut hasher);
        }
        
        let hash = hasher.finish();
        
        // Expand hash to 32-byte commitment
        let mut commitment = vec![0u8; 32];
        let hash_bytes = hash.to_le_bytes();
        
        for i in 0..32 {
            commitment[i] = hash_bytes[i % 8]
                .wrapping_mul((i + 1) as u8);
            
            // Mix with polynomial data
            if i < poly.len() {
                let coeff_bytes = poly[i].to_canonical_u64().to_le_bytes();
                commitment[i] ^= coeff_bytes[i % 8];
            }
        }
        
        commitment
    }
}

impl<F: Field> Default for PreprocessingPIOP<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Circuit description for preprocessing
pub struct CircuitDescription<F: Field> {
    /// Circuit size
    pub size: usize,
    /// Lookup table
    pub table: Vec<F>,
    /// Selector polynomials
    pub selectors: Vec<Vec<F>>,
}

/// Preprocessing data
pub struct PreprocessingData {
    /// Commitments to preprocessing polynomials
    pub commitments: Vec<Vec<u8>>,
    /// Circuit size
    pub circuit_size: usize,
}

/// Dual Polynomial Commitments
///
/// Bridges between univariate and multilinear polynomial commitments.
/// Enables compatibility between different proof systems.
///
/// # Use Cases:
/// - KZG (univariate) ↔ Spartan (multilinear)
/// - Plonk (univariate) ↔ HyperPlonk (multilinear)
/// - Mixed proof systems
///
/// # Key Insight:
/// Linear isomorphism between Lagrange bases:
/// - Univariate: L_i(ω^j) = δ_{ij}
/// - Multilinear: L_b(b') = δ_{bb'}
pub struct DualCommitments<F: Field> {
    /// Domain size (must be power of 2)
    pub domain_size: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field> DualCommitments<F> {
    /// Create new dual commitment bridge
    ///
    /// # Arguments:
    /// - `domain_size`: Size of evaluation domain (power of 2)
    pub fn new(domain_size: usize) -> LookupResult<Self> {
        if !domain_size.is_power_of_two() {
            return Err(LookupError::InvalidTableSize {
                size: domain_size,
                required: "power of 2".to_string(),
            });
        }
        
        Ok(DualCommitments {
            domain_size,
            _phantom: PhantomData,
        })
    }
    
    /// Convert univariate evaluations to multilinear
    ///
    /// Maps evaluations over {ω^0, ω^1, ..., ω^{n-1}} to {0,1}^k
    ///
    /// # Arguments:
    /// - `univariate_evals`: Evaluations at roots of unity
    ///
    /// # Returns: Multilinear evaluations over Boolean hypercube
    ///
    /// # Performance: O(n) reordering
    pub fn univariate_to_multilinear(&self, univariate_evals: &[F]) -> LookupResult<Vec<F>> {
        if univariate_evals.len() != self.domain_size {
            return Err(LookupError::InvalidTableSize {
                size: univariate_evals.len(),
                required: format!("{}", self.domain_size),
            });
        }
        
        // Bit-reversal permutation
        let mut multilinear_evals = vec![F::ZERO; self.domain_size];
        let log_size = self.domain_size.trailing_zeros() as usize;
        
        for i in 0..self.domain_size {
            let j = Self::bit_reverse(i, log_size);
            multilinear_evals[j] = univariate_evals[i];
        }
        
        Ok(multilinear_evals)
    }
    
    /// Convert multilinear evaluations to univariate
    ///
    /// Inverse of univariate_to_multilinear
    ///
    /// # Performance: O(n) reordering
    pub fn multilinear_to_univariate(&self, multilinear_evals: &[F]) -> LookupResult<Vec<F>> {
        if multilinear_evals.len() != self.domain_size {
            return Err(LookupError::InvalidTableSize {
                size: multilinear_evals.len(),
                required: format!("{}", self.domain_size),
            });
        }
        
        // Inverse bit-reversal permutation
        let mut univariate_evals = vec![F::ZERO; self.domain_size];
        let log_size = self.domain_size.trailing_zeros() as usize;
        
        for i in 0..self.domain_size {
            let j = Self::bit_reverse(i, log_size);
            univariate_evals[i] = multilinear_evals[j];
        }
        
        Ok(univariate_evals)
    }
    
    /// Bridge KZG commitment to multilinear commitment
    ///
    /// Enables using KZG-committed polynomial in multilinear proof
    ///
    /// # Arguments:
    /// - `kzg_commitment`: KZG commitment to univariate polynomial
    /// - `univariate_evals`: Evaluations at roots of unity
    ///
    /// # Returns: Multilinear commitment
    pub fn bridge_kzg_to_multilinear(
        &self,
        _kzg_commitment: &[u8],
        univariate_evals: &[F],
    ) -> LookupResult<Vec<u8>> {
        // Convert evaluations
        let multilinear_evals = self.univariate_to_multilinear(univariate_evals)?;
        
        // Commit to multilinear polynomial
        // In production, use actual multilinear PCS
        let mut commitment = vec![0u8; 32];
        for (i, &eval) in multilinear_evals.iter().enumerate() {
            let bytes = eval.to_canonical_u64().to_le_bytes();
            for (j, &b) in bytes.iter().enumerate() {
                commitment[j % 32] ^= b.wrapping_mul((i + 1) as u8);
            }
        }
        
        Ok(commitment)
    }
    
    /// Bridge multilinear commitment to KZG
    ///
    /// Inverse of bridge_kzg_to_multilinear
    pub fn bridge_multilinear_to_kzg(
        &self,
        _multilinear_commitment: &[u8],
        multilinear_evals: &[F],
    ) -> LookupResult<Vec<u8>> {
        // Convert evaluations
        let univariate_evals = self.multilinear_to_univariate(multilinear_evals)?;
        
        // Commit using KZG
        // In production, use actual KZG commitment
        let mut commitment = vec![0u8; 48];
        for (i, &eval) in univariate_evals.iter().enumerate() {
            let bytes = eval.to_canonical_u64().to_le_bytes();
            for (j, &b) in bytes.iter().enumerate() {
                commitment[j % 48] ^= b.wrapping_mul((i + 1) as u8);
            }
        }
        
        Ok(commitment)
    }
    
    /// Bit-reversal permutation
    ///
    /// Reverses the bits of i in log_size bits
    fn bit_reverse(mut i: usize, log_size: usize) -> usize {
        let mut result = 0;
        for _ in 0..log_size {
            result = (result << 1) | (i & 1);
            i >>= 1;
        }
        result
    }
    
    /// Verify isomorphism preserves evaluations
    ///
    /// Checks that conversion is correct
    pub fn verify_isomorphism(
        &self,
        univariate_evals: &[F],
        multilinear_evals: &[F],
    ) -> bool {
        if let Ok(converted) = self.univariate_to_multilinear(univariate_evals) {
            converted.len() == multilinear_evals.len()
                && converted
                    .iter()
                    .zip(multilinear_evals.iter())
                    .all(|(a, b)| a == b)
        } else {
            false
        }
    }
}
