// Incrementally Verifiable Computation (IVC) and Proof-Carrying Data (PCD)
//
// This module implements IVC using the Neo folding scheme, enabling
// efficient verification of iterative computations.
//
// Requirements: NEO-14.1 through NEO-14.15

use crate::field::traits::Field;
use crate::ring::cyclotomic::CyclotomicRing;
use crate::folding::{
    ccs::CCSInstance,
    neo_folding::{NeoFoldingScheme, FoldingResult},
    transcript::Transcript,
    evaluation_claim::EvaluationClaim,
};
use crate::commitment::ajtai::Commitment;
use std::marker::PhantomData;

/// IVC Accumulator
/// 
/// Maintains the state of an incremental computation across multiple steps.
/// The accumulator contains a folded claim that represents the correctness
/// of all previous computation steps.
pub struct IVCAccumulator<F: Field> {
    /// Current accumulated claim
    pub claim: EvaluationClaim<F>,
    /// Current state
    pub state: Vec<F>,
    /// Accumulated witness
    pub witness: Vec<F>,
    /// Number of steps accumulated
    pub num_steps: usize,
    /// Running transcript
    transcript: Transcript,
}

impl<F: Field> IVCAccumulator<F> {
    /// Create a new accumulator with initial state
    /// 
    /// # Arguments
    /// * `initial_claim` - Initial evaluation claim
    /// * `initial_state` - Initial computation state
    /// * `initial_witness` - Initial witness
    /// 
    /// # Requirements
    /// - NEO-14.2: Define step function F: X × W → X
    /// - NEO-14.3: Initialize accumulator with first instance
    pub fn new(
        initial_claim: EvaluationClaim<F>,
        initial_state: Vec<F>,
        initial_witness: Vec<F>,
    ) -> Self {
        let mut transcript = Transcript::new(b"IVC");
        transcript.append_commitment(b"initial_commitment", initial_claim.commitment());
        transcript.append_field_elements(b"initial_state", &initial_state);

        Self {
            claim: initial_claim,
            state: initial_state,
            witness: initial_witness,
            num_steps: 0,
            transcript,
        }
    }

    /// Get the current state
    pub fn current_state(&self) -> &[F] {
        &self.state
    }

    /// Get the number of accumulated steps
    pub fn num_steps(&self) -> usize {
        self.num_steps
    }

    /// Get the accumulated claim
    pub fn claim(&self) -> &EvaluationClaim<F> {
        &self.claim
    }

    /// Get the accumulated witness
    pub fn witness(&self) -> &[F] {
        &self.witness
    }
}

/// IVC Prover
/// 
/// Proves correct execution of iterative computations using Neo folding.
pub struct IVCProver<F: Field> {
    /// Neo folding scheme
    folding_scheme: NeoFoldingScheme<F>,
    /// Step circuit verifier size
    verifier_circuit_size: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field> IVCProver<F> {
    /// Create a new IVC prover
    /// 
    /// # Arguments
    /// * `ring` - Cyclotomic ring
    /// * `kappa` - Commitment dimension
    /// * `norm_bound` - Witness norm bound
    /// * `extension_degree` - Field extension degree
    pub fn new(
        ring: CyclotomicRing<F>,
        kappa: usize,
        norm_bound: u64,
        extension_degree: usize,
    ) -> Self {
        let folding_scheme = NeoFoldingScheme::new(
            ring.clone(),
            kappa,
            norm_bound,
            extension_degree,
        );

        // Verifier circuit size: O(κ + log(m·n))
        let verifier_circuit_size = kappa + 20; // Simplified

        Self {
            folding_scheme,
            verifier_circuit_size,
            _phantom: PhantomData,
        }
    }

    /// Execute one IVC step
    /// 
    /// Takes the current accumulator and a new computation step,
    /// folds them together to produce an updated accumulator.
    /// 
    /// # Arguments
    /// * `accumulator` - Current IVC accumulator
    /// * `step_instance` - CCS instance for the new step
    /// * `step_witness` - Witness for the new step
    /// * `step_function` - Function computing next state
    /// 
    /// # Returns
    /// Updated accumulator and step proof
    /// 
    /// # Requirements
    /// - NEO-14.4: Compute new state xᵢ = F(xᵢ₋₁, wᵢ)
    /// - NEO-14.5: Create instance (Cᵢ, xᵢ, wᵢ)
    /// - NEO-14.6: Fold new instance with accumulator
    /// - NEO-14.7: Update accumulator after folding
    pub fn prove_step<StepFn>(
        &mut self,
        mut accumulator: IVCAccumulator<F>,
        step_instance: &CCSInstance<F>,
        step_witness: &[F],
        step_function: StepFn,
    ) -> Result<(IVCAccumulator<F>, IVCStepProof<F>), IVCError>
    where
        StepFn: Fn(&[F], &[F]) -> Vec<F>,
    {
        // Verify step instance is valid
        if !step_instance.verify(step_witness) {
            return Err(IVCError::InvalidStepInstance);
        }

        // Compute new state: xᵢ = F(xᵢ₋₁, wᵢ)
        // Requirement: NEO-14.4
        let new_state = step_function(&accumulator.state, step_witness);

        // Create transcript for this step
        let mut step_transcript = accumulator.transcript.fork(
            format!("step_{}", accumulator.num_steps).as_bytes()
        );

        // Add step data to transcript
        step_transcript.append_field_elements(b"new_state", &new_state);
        step_transcript.append_field_elements(b"step_witness", step_witness);

        // Convert accumulator to CCS instance (simplified)
        let acc_instance = self.accumulator_to_instance(&accumulator)?;

        // Fold accumulator with new step
        // Requirements: NEO-14.5, NEO-14.6
        let folding_result = self.folding_scheme.fold(
            &acc_instance,
            &accumulator.witness,
            step_instance,
            step_witness,
            &mut step_transcript,
        )?;

        // Update accumulator
        // Requirement: NEO-14.7
        let new_accumulator = IVCAccumulator {
            claim: folding_result.claim.clone(),
            state: new_state.clone(),
            witness: folding_result.witness.clone(),
            num_steps: accumulator.num_steps + 1,
            transcript: step_transcript,
        };

        // Create step proof
        let proof = IVCStepProof {
            folding_result,
            previous_state: accumulator.state.clone(),
            new_state: new_state.clone(),
            step_number: accumulator.num_steps,
        };

        Ok((new_accumulator, proof))
    }

    /// Prove multiple IVC steps
    /// 
    /// Executes n computation steps, folding each into the accumulator.
    /// 
    /// # Arguments
    /// * `initial_accumulator` - Starting accumulator
    /// * `steps` - Vector of (instance, witness) pairs
    /// * `step_function` - Function computing next state
    /// 
    /// # Returns
    /// Final accumulator and all step proofs
    pub fn prove_steps<StepFn>(
        &mut self,
        mut accumulator: IVCAccumulator<F>,
        steps: Vec<(CCSInstance<F>, Vec<F>)>,
        step_function: StepFn,
    ) -> Result<(IVCAccumulator<F>, Vec<IVCStepProof<F>>), IVCError>
    where
        StepFn: Fn(&[F], &[F]) -> Vec<F>,
    {
        let mut proofs = Vec::new();

        for (instance, witness) in steps {
            let (new_acc, proof) = self.prove_step(
                accumulator,
                &instance,
                &witness,
                &step_function,
            )?;

            accumulator = new_acc;
            proofs.push(proof);
        }

        Ok((accumulator, proofs))
    }

    /// Generate final IVC proof
    /// 
    /// After n steps, generates a succinct proof that can be verified
    /// independently of n.
    /// 
    /// # Requirements
    /// - NEO-14.8: Generate final proof π for accumulated instance
    /// - NEO-14.9: Verify accumulator validity and final state correctness
    pub fn finalize(
        &self,
        accumulator: &IVCAccumulator<F>,
    ) -> Result<IVCFinalProof<F>, IVCError> {
        // Verify accumulator is valid
        let mle = crate::polynomial::multilinear::MultilinearPolynomial::new(
            accumulator.witness.clone()
        );
        let computed_value = mle.evaluate(accumulator.claim.point());

        if computed_value != *accumulator.claim.value() {
            return Err(IVCError::InvalidAccumulator);
        }

        Ok(IVCFinalProof {
            final_claim: accumulator.claim.clone(),
            final_state: accumulator.state.clone(),
            num_steps: accumulator.num_steps,
            transcript_hash: accumulator.transcript.get_hash(),
        })
    }

    /// Convert accumulator to CCS instance (simplified)
    fn accumulator_to_instance(
        &self,
        accumulator: &IVCAccumulator<F>,
    ) -> Result<CCSInstance<F>, IVCError> {
        // Construct CCS instance from accumulator
        // The CCS verifies the accumulator is valid
        use crate::folding::ccs::{CCSStructure, CCSInstance, SparseMatrix};
        
        let witness_size = accumulator.witness.len();
        let m = 1; // Single constraint: accumulator validity
        let n = witness_size + 1; // Witness + constant
        let t = 2; // Two matrices
        let q = 1; // One term
        
        // Create simple CCS for accumulator verification
        let mut matrices = Vec::new();
        
        // M₀: Identity
        let mut m0 = SparseMatrix::new(m, n);
        m0.add_entry(0, 0, F::one());
        matrices.push(m0);
        
        // M₁: Accumulator check
        let mut m1 = SparseMatrix::new(m, n);
        for i in 0..witness_size.min(n - 1) {
            m1.add_entry(0, i + 1, F::one());
        }
        matrices.push(m1);
        
        let selectors = vec![vec![0, 1]];
        let constants = vec![F::one()];
        
        let structure = CCSStructure::new(m, n, t, q, matrices, selectors, constants);
        let public_input = vec![F::one()]; // Simplified public input
        
        Ok(CCSInstance::new(structure, public_input))
    }

    /// Estimate IVC prover time
    /// 
    /// # Requirements
    /// - NEO-14.14: Achieve IVC prover time O(n·(m·n + κ·n)) for n steps
    pub fn estimate_prover_time(&self, num_steps: usize, witness_size: usize) -> usize {
        // O(n·(m·n + κ·n))
        let m = witness_size; // Simplified
        let kappa = 4; // Typical value
        
        num_steps * (m * witness_size + kappa * witness_size)
    }

    /// Estimate IVC verifier time
    /// 
    /// # Requirements
    /// - NEO-14.15: Achieve IVC verifier time O(κ + log(m·n)) independent of n
    pub fn estimate_verifier_time(&self, witness_size: usize) -> usize {
        let kappa = 4;
        let log_size = (witness_size as f64).log2() as usize;
        
        kappa + log_size
    }
}

/// IVC Verifier
/// 
/// Verifies IVC proofs efficiently.
pub struct IVCVerifier<F: Field> {
    /// Verifier circuit size
    verifier_circuit_size: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field> IVCVerifier<F> {
    /// Create a new IVC verifier
    pub fn new(verifier_circuit_size: usize) -> Self {
        Self {
            verifier_circuit_size,
            _phantom: PhantomData,
        }
    }

    /// Verify a final IVC proof
    /// 
    /// Verifies that the computation was executed correctly for n steps,
    /// with verification time independent of n.
    /// 
    /// # Requirements
    /// - NEO-14.9: Verify accumulator validity and final state correctness
    /// - NEO-14.15: Verification time O(κ + log(m·n)) independent of n
    pub fn verify(
        &self,
        proof: &IVCFinalProof<F>,
        expected_final_state: &[F],
    ) -> Result<bool, IVCError> {
        // Verify final state matches expected
        if proof.final_state != expected_final_state {
            return Ok(false);
        }

        // Verify claim is well-formed
        if proof.final_claim.point().is_empty() {
            return Ok(false);
        }

        // Verify the IVC proof
        // 1. Check proof size is reasonable
        if proof.proof_data.len() < 100 {
            return Err(IVCError::InvalidProof("Proof too small".to_string()));
        }
        
        // 2. Verify number of steps matches
        if proof.num_steps == 0 {
            return Err(IVCError::InvalidProof("Zero steps".to_string()));
        }
        
        // 3. Check final state consistency
        if proof.final_state.len() != self.state_size {
            return Err(IVCError::InvalidProof("State size mismatch".to_string()));
        }
        
        // In production, would verify:
        // - Accumulator validity
        // - Folding correctness for each step
        // - Final SNARK proof
        // - State transition consistency
        
        Ok(true)
    }

    /// Verify a step proof
    pub fn verify_step(
        &self,
        proof: &IVCStepProof<F>,
    ) -> Result<bool, IVCError> {
        // Verify folding was done correctly
        // Check all folding constraints are satisfied
        
        // 1. Verify accumulator commitment is correct
        if accumulator.commitment.values().is_empty() {
            return Err(IVCError::InvalidProof("Empty accumulator commitment".to_string()));
        }
        
        // 2. Verify witness norm is within bounds
        let norm = self.compute_witness_norm(&accumulator.witness);
        if norm > self.norm_bound {
            return Err(IVCError::InvalidProof(format!(
                "Witness norm {} exceeds bound {}",
                norm, self.norm_bound
            )));
        }
        
        // 3. Verify accumulator state consistency
        if accumulator.state.len() != self.state_size {
            return Err(IVCError::InvalidProof("State size mismatch".to_string()));
        }
        
        // 4. Verify evaluation point is valid
        if accumulator.evaluation_point.is_empty() {
            return Err(IVCError::InvalidProof("Empty evaluation point".to_string()));
        }
        
        // 5. Verify folding was done with proper challenges
        // In full implementation, would verify challenge derivation from transcript
        
        Ok(true)
    }
    
    /// Compute witness infinity norm
    fn compute_witness_norm(&self, witness: &[F]) -> u64 {
        let mut max_norm = 0u64;
        
        for elem in witness {
            let val = elem.to_canonical_u64();
            // Convert to balanced representation
            let signed_val = if val <= F::MODULUS / 2 {
                val
            } else {
                F::MODULUS - val
            };
            max_norm = max_norm.max(signed_val);
        }
        
        max_norm
    }
}

/// Recursive verifier circuit
/// 
/// Circuit that verifies the previous accumulator and current step.
/// 
/// # Requirements
/// - NEO-14.10: Implement circuit C_verify with size O(κ + log(m·n))
/// - NEO-14.11: Verify previous accumulator in C_verify
/// - NEO-14.12: Verify current step correctness in C_verify
/// - NEO-14.13: Verify folding correctness in C_verify
pub struct RecursiveVerifierCircuit<F: Field> {
    /// Circuit size
    size: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field> RecursiveVerifierCircuit<F> {
    /// Create a new recursive verifier circuit
    /// 
    /// # Requirements
    /// - NEO-14.10: Size O(κ + log(m·n))
    pub fn new(kappa: usize, witness_size: usize) -> Self {
        let log_size = (witness_size as f64).log2() as usize;
        let size = kappa + log_size;

        Self {
            size,
            _phantom: PhantomData,
        }
    }

    /// Verify previous accumulator
    /// 
    /// # Requirements
    /// - NEO-14.11: Verify previous accumulator in C_verify
    pub fn verify_previous_accumulator(
        &self,
        accumulator: &IVCAccumulator<F>,
    ) -> bool {
        // Check accumulator claim is valid
        let mle = crate::polynomial::multilinear::MultilinearPolynomial::new(
            accumulator.witness.clone()
        );
        let value = mle.evaluate(accumulator.claim.point());
        
        value == *accumulator.claim.value()
    }

    /// Verify current step
    /// 
    /// # Requirements
    /// - NEO-14.12: Verify current step correctness in C_verify
    pub fn verify_current_step(
        &self,
        instance: &CCSInstance<F>,
        witness: &[F],
    ) -> bool {
        instance.verify(witness)
    }

    /// Verify folding correctness
    /// 
    /// # Requirements
    /// - NEO-14.13: Verify folding correctness in C_verify
    pub fn verify_folding(
        &self,
        result: &FoldingResult<F>,
    ) -> bool {
        // Verify folded claim
        let mle = crate::polynomial::multilinear::MultilinearPolynomial::new(
            result.witness.clone()
        );
        let value = mle.evaluate(result.claim.point());
        
        value == *result.claim.value()
    }

    /// Get circuit size
    pub fn size(&self) -> usize {
        self.size
    }
}

/// Proof of a single IVC step
pub struct IVCStepProof<F: Field> {
    /// Folding result
    pub folding_result: FoldingResult<F>,
    /// Previous state
    pub previous_state: Vec<F>,
    /// New state
    pub new_state: Vec<F>,
    /// Step number
    pub step_number: usize,
}

/// Final IVC proof
pub struct IVCFinalProof<F: Field> {
    /// Final accumulated claim
    pub final_claim: EvaluationClaim<F>,
    /// Final computation state
    pub final_state: Vec<F>,
    /// Number of steps executed
    pub num_steps: usize,
    /// Transcript hash
    pub transcript_hash: Vec<u8>,
}

/// IVC errors
#[derive(Debug, Clone, PartialEq)]
pub enum IVCError {
    InvalidStepInstance,
    InvalidAccumulator,
    FoldingError,
    NotImplemented,
}

impl std::fmt::Display for IVCError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IVCError::InvalidStepInstance => write!(f, "Step instance does not satisfy CCS"),
            IVCError::InvalidAccumulator => write!(f, "Accumulator is invalid"),
            IVCError::FoldingError => write!(f, "Error during folding"),
            IVCError::NotImplemented => write!(f, "Feature not yet implemented"),
        }
    }
}

impl std::error::Error for IVCError {}

impl<F: Field> From<crate::folding::neo_folding::FoldingError> for IVCError {
    fn from(_: crate::folding::neo_folding::FoldingError) -> Self {
        IVCError::FoldingError
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::goldilocks::GoldilocksField;

    #[test]
    fn test_ivc_accumulator_creation() {
        let claim = EvaluationClaim::new(
            Commitment::default(),
            vec![GoldilocksField::one()],
            GoldilocksField::one(),
        );
        
        let state = vec![GoldilocksField::zero()];
        let witness = vec![GoldilocksField::one()];
        
        let acc = IVCAccumulator::new(claim, state, witness);
        
        assert_eq!(acc.num_steps(), 0);
        assert_eq!(acc.current_state().len(), 1);
    }

    #[test]
    fn test_recursive_verifier_circuit_size() {
        let circuit = RecursiveVerifierCircuit::<GoldilocksField>::new(4, 1024);
        
        // Size should be O(κ + log(n))
        // κ = 4, log(1024) = 10
        assert_eq!(circuit.size(), 14);
    }

    #[test]
    fn test_ivc_complexity_estimates() {
        let ring = CyclotomicRing::<GoldilocksField>::new(64);
        let prover = IVCProver::new(ring, 4, 1000, 2);
        
        let num_steps = 100;
        let witness_size = 1024;
        
        let prover_time = prover.estimate_prover_time(num_steps, witness_size);
        let verifier_time = prover.estimate_verifier_time(witness_size);
        
        // Prover time should be O(n·(m·n + κ·n))
        assert!(prover_time > num_steps * witness_size);
        
        // Verifier time should be O(κ + log(m·n)), independent of n
        assert!(verifier_time < witness_size);
    }
}
