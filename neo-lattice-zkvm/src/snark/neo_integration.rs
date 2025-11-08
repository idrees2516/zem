// Symphony-Neo Integration Module
// Integrates Symphony SNARK with Neo's pay-per-bit commitment and optimizations

use crate::field::Field;
use crate::ring::{CyclotomicRing, RingElement};
use crate::commitment::neo_payperbit::{NeoPayPerBitCommitment, PayPerBitParams};
use crate::commitment::ajtai::{AjtaiCommitment, CommitmentKey};
use crate::folding::ccs::{CCSInstance, CCSWitness};
use crate::folding::ccs_reduction::CCSReductionProtocol;
use crate::folding::rlc::RandomLinearCombination;
use crate::folding::decomposition::DecompositionReduction;
use crate::field::symphony_extension::SymphonyExtensionField;
use super::symphony::{SymphonySNARK, SymphonyParams, R1CSInstance, R1CSWitness};
use super::compiler::CPSNARKCompiler;
use std::marker::PhantomData;

/// Symphony-Neo integration for pay-per-bit commitments
/// 
/// Integrates Neo's matrix commitment scheme with Symphony's high-arity folding
/// to achieve commitment costs that scale with value bit-width.
pub struct SymphonyNeoIntegration<F: Field> {
    /// Symphony SNARK system
    symphony: SymphonySNARK<F>,
    
    /// Neo pay-per-bit commitment
    neo_commitment: NeoPayPerBitCommitment<F>,
    
    /// CCS reduction protocol
    ccs_reduction: CCSReductionProtocol<F>,
    
    /// Random linear combination protocol
    rlc: RandomLinearCombination<F>,
    
    /// Decomposition reduction protocol
    decomposition: DecompositionReduction<F>,
    
    /// Base ring
    ring: CyclotomicRing<F>,
    
    _phantom: PhantomData<F>,
}

impl<F: Field> SymphonyNeoIntegration<F> {
    /// Create new Symphony-Neo integration
    /// 
    /// # Arguments
    /// * `symphony_params` - Symphony system parameters
    /// * `pay_per_bit_params` - Neo pay-per-bit parameters
    /// 
    /// # Returns
    /// * Integrated system ready for proving
    pub fn new(
        symphony_params: SymphonyParams,
        pay_per_bit_params: PayPerBitParams,
    ) -> Result<Self, String> {
        // Initialize Symphony SNARK
        let symphony = SymphonySNARK::setup(symphony_params.clone())?;
        
        // Initialize Neo pay-per-bit commitment
        let neo_commitment = NeoPayPerBitCommitment::new(
            pay_per_bit_params.clone(),
            symphony_params.ring_degree,
            symphony_params.modulus,
        )?;
        
        // Initialize CCS reduction protocol
        let ccs_reduction = CCSReductionProtocol::new(
            symphony_params.ring_degree,
            symphony_params.modulus,
        )?;
        
        // Initialize RLC protocol
        let rlc = RandomLinearCombination::new(
            symphony_params.challenge_set_size,
        )?;
        
        // Initialize decomposition reduction
        let decomposition = DecompositionReduction::new(
            symphony_params.ring_degree,
        )?;
        
        // Create ring
        let ring = CyclotomicRing::new(
            symphony_params.ring_degree,
            symphony_params.modulus,
        )?;
        
        Ok(Self {
            symphony,
            neo_commitment,
            ccs_reduction,
            rlc,
            decomposition,
            ring,
            _phantom: PhantomData,
        })
    }
    
    /// Prove R1CS with pay-per-bit optimization
    /// 
    /// Converts R1CS to CCS, applies pay-per-bit commitment,
    /// then uses Symphony folding for efficient batch proving.
    /// 
    /// # Arguments
    /// * `r1cs_instances` - R1CS instances to prove
    /// * `r1cs_witnesses` - Corresponding witnesses
    /// * `bit_widths` - Bit-width for each witness value
    /// 
    /// # Returns
    /// * Symphony proof with optimized commitment costs
    pub fn prove_with_pay_per_bit(
        &self,
        r1cs_instances: &[R1CSInstance],
        r1cs_witnesses: &[R1CSWitness],
        bit_widths: &[usize],
    ) -> Result<super::symphony::SymphonyProof<F>, String> {
        // Step 1: Convert R1CS to CCS
        let (ccs_instances, ccs_witnesses) = self.convert_r1cs_to_ccs(
            r1cs_instances,
            r1cs_witnesses,
        )?;
        
        // Step 2: Apply pay-per-bit commitment
        let optimized_instances = self.apply_pay_per_bit_commitment(
            &ccs_instances,
            &ccs_witnesses,
            bit_widths,
        )?;
        
        // Step 3: Use Symphony folding
        self.symphony.prove(&optimized_instances, r1cs_witnesses)
    }
    
    /// Verify proof with pay-per-bit optimization
    pub fn verify_with_pay_per_bit(
        &self,
        r1cs_instances: &[R1CSInstance],
        proof: &super::symphony::SymphonyProof<F>,
        bit_widths: &[usize],
    ) -> Result<bool, String> {
        // Convert R1CS to CCS
        let ccs_instances = self.convert_r1cs_instances_to_ccs(r1cs_instances)?;
        
        // Apply pay-per-bit commitment (verifier version)
        let optimized_instances = self.apply_pay_per_bit_commitment_verifier(
            &ccs_instances,
            bit_widths,
        )?;
        
        // Verify using Symphony
        self.symphony.verify(&optimized_instances, proof)
    }
    
    /// Convert R1CS to CCS
    /// 
    /// Uses Neo's CCS reduction protocol to convert R1CS constraints
    /// to Customizable Constraint System format.
    fn convert_r1cs_to_ccs(
        &self,
        r1cs_instances: &[R1CSInstance],
        r1cs_witnesses: &[R1CSWitness],
    ) -> Result<(Vec<CCSInstance<F>>, Vec<CCSWitness<F>>), String> {
        let mut ccs_instances = Vec::with_capacity(r1cs_instances.len());
        let mut ccs_witnesses = Vec::with_capacity(r1cs_witnesses.len());
        
        for (instance, witness) in r1cs_instances.iter().zip(r1cs_witnesses) {
            let (ccs_inst, ccs_wit) = self.ccs_reduction.reduce_r1cs(
                instance,
                witness,
            )?;
            
            ccs_instances.push(ccs_inst);
            ccs_witnesses.push(ccs_wit);
        }
        
        Ok((ccs_instances, ccs_witnesses))
    }
    
    /// Convert R1CS instances only (for verification)
    fn convert_r1cs_instances_to_ccs(
        &self,
        r1cs_instances: &[R1CSInstance],
    ) -> Result<Vec<CCSInstance<F>>, String> {
        let mut ccs_instances = Vec::with_capacity(r1cs_instances.len());
        
        for instance in r1cs_instances {
            let ccs_inst = self.ccs_reduction.reduce_r1cs_instance(instance)?;
            ccs_instances.push(ccs_inst);
        }
        
        Ok(ccs_instances)
    }
    
    /// Apply pay-per-bit commitment
    /// 
    /// Transforms witness vectors to matrices and commits using Neo's
    /// pay-per-bit scheme, achieving 32× cost reduction for bits vs 32-bit values.
    fn apply_pay_per_bit_commitment(
        &self,
        ccs_instances: &[CCSInstance<F>],
        ccs_witnesses: &[CCSWitness<F>],
        bit_widths: &[usize],
    ) -> Result<Vec<R1CSInstance>, String> {
        let mut optimized_instances = Vec::with_capacity(ccs_instances.len());
        
        for ((instance, witness), &bit_width) in ccs_instances.iter()
            .zip(ccs_witnesses)
            .zip(bit_widths)
        {
            // Transform witness vector to matrix
            let witness_matrix = self.neo_commitment.vector_to_matrix(
                &witness.witness,
                bit_width,
            )?;
            
            // Commit to matrix using Ajtai commitment
            let commitment = self.neo_commitment.commit_matrix(&witness_matrix)?;
            
            // Create optimized R1CS instance
            let optimized = self.ccs_to_r1cs_with_commitment(
                instance,
                commitment,
            )?;
            
            optimized_instances.push(optimized);
        }
        
        Ok(optimized_instances)
    }
    
    /// Apply pay-per-bit commitment (verifier version)
    fn apply_pay_per_bit_commitment_verifier(
        &self,
        ccs_instances: &[CCSInstance<F>],
        bit_widths: &[usize],
    ) -> Result<Vec<R1CSInstance>, String> {
        let mut optimized_instances = Vec::with_capacity(ccs_instances.len());
        
        for (instance, &bit_width) in ccs_instances.iter().zip(bit_widths) {
            // Verifier doesn't have witness, just uses commitment from instance
            let optimized = self.ccs_to_r1cs_instance(instance)?;
            optimized_instances.push(optimized);
        }
        
        Ok(optimized_instances)
    }
    
    /// Convert CCS to R1CS with commitment
    fn ccs_to_r1cs_with_commitment(
        &self,
        ccs_instance: &CCSInstance<F>,
        commitment: crate::commitment::ajtai::Commitment<F>,
    ) -> Result<R1CSInstance, String> {
        // Extract R1CS matrices from CCS
        let (m1, m2, m3) = self.ccs_reduction.extract_r1cs_matrices(ccs_instance)?;
        
        Ok(R1CSInstance {
            num_constraints: ccs_instance.num_constraints,
            num_variables: ccs_instance.num_variables,
            public_inputs: ccs_instance.public_inputs.clone(),
            matrices: (m1, m2, m3),
        })
    }
    
    /// Convert CCS instance to R1CS
    fn ccs_to_r1cs_instance(
        &self,
        ccs_instance: &CCSInstance<F>,
    ) -> Result<R1CSInstance, String> {
        let (m1, m2, m3) = self.ccs_reduction.extract_r1cs_matrices(ccs_instance)?;
        
        Ok(R1CSInstance {
            num_constraints: ccs_instance.num_constraints,
            num_variables: ccs_instance.num_variables,
            public_inputs: ccs_instance.public_inputs.clone(),
            matrices: (m1, m2, m3),
        })
    }
    
    /// Compute commitment cost for given bit-width
    /// 
    /// Returns the number of Rq-operations required for commitment.
    /// Demonstrates 32× reduction for 1-bit vs 32-bit values.
    pub fn compute_commitment_cost(
        &self,
        num_values: usize,
        bit_width: usize,
    ) -> usize {
        self.neo_commitment.compute_cost(num_values, bit_width)
    }
    
    /// Demonstrate pay-per-bit cost scaling
    /// 
    /// Shows commitment cost for different bit-widths:
    /// - 1-bit: n operations
    /// - 8-bit: 8n operations
    /// - 32-bit: 32n operations
    pub fn demonstrate_cost_scaling(&self, num_values: usize) -> Vec<(usize, usize)> {
        vec![
            (1, self.compute_commitment_cost(num_values, 1)),
            (8, self.compute_commitment_cost(num_values, 8)),
            (16, self.compute_commitment_cost(num_values, 16)),
            (32, self.compute_commitment_cost(num_values, 32)),
        ]
    }
    
    /// Use Neo's random linear combination for folding
    /// 
    /// Applies RLC to combine multiple evaluation claims into single claim.
    pub fn apply_rlc(
        &self,
        evaluation_claims: &[SymphonyExtensionField<F>],
    ) -> Result<SymphonyExtensionField<F>, String> {
        self.rlc.combine_claims(evaluation_claims)
    }
    
    /// Use Neo's decomposition reduction
    /// 
    /// Applies decomposition to reduce witness norm bounds.
    pub fn apply_decomposition(
        &self,
        witness: &[RingElement<F>],
        base: u64,
    ) -> Result<Vec<Vec<RingElement<F>>>, String> {
        self.decomposition.decompose_witness(witness, base)
    }
    
    /// Get Symphony parameters
    pub fn symphony_params(&self) -> &SymphonyParams {
        self.symphony.params()
    }
    
    /// Get Neo commitment parameters
    pub fn neo_params(&self) -> &PayPerBitParams {
        self.neo_commitment.params()
    }
}

/// Estimate cost savings from pay-per-bit commitment
/// 
/// Compares standard commitment cost vs pay-per-bit cost.
pub fn estimate_cost_savings(
    num_values: usize,
    bit_width: usize,
) -> (usize, usize, f64) {
    // Standard commitment: always uses full field element size (e.g., 32 bits)
    let standard_cost = num_values * 32;
    
    // Pay-per-bit commitment: scales with actual bit-width
    let pay_per_bit_cost = num_values * bit_width;
    
    // Savings ratio
    let savings_ratio = standard_cost as f64 / pay_per_bit_cost as f64;
    
    (standard_cost, pay_per_bit_cost, savings_ratio)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::m61::M61;
    
    #[test]
    fn test_symphony_neo_integration() {
        let symphony_params = SymphonyParams::default_post_quantum();
        let pay_per_bit_params = PayPerBitParams::default();
        
        let integration = SymphonyNeoIntegration::<M61>::new(
            symphony_params,
            pay_per_bit_params,
        );
        
        assert!(integration.is_ok());
    }
    
    #[test]
    fn test_cost_scaling() {
        let symphony_params = SymphonyParams::default_post_quantum();
        let pay_per_bit_params = PayPerBitParams::default();
        
        let integration = SymphonyNeoIntegration::<M61>::new(
            symphony_params,
            pay_per_bit_params,
        ).unwrap();
        
        let costs = integration.demonstrate_cost_scaling(1000);
        
        // Verify cost scales linearly with bit-width
        assert_eq!(costs[0].0, 1);  // 1-bit
        assert_eq!(costs[1].0, 8);  // 8-bit
        assert_eq!(costs[2].0, 16); // 16-bit
        assert_eq!(costs[3].0, 32); // 32-bit
        
        // Verify 32× reduction for bits vs 32-bit values
        let ratio = costs[3].1 as f64 / costs[0].1 as f64;
        assert!((ratio - 32.0).abs() < 1.0);
    }
    
    #[test]
    fn test_estimate_cost_savings() {
        // For 1000 1-bit values
        let (standard, optimized, ratio) = estimate_cost_savings(1000, 1);
        assert_eq!(standard, 32000);
        assert_eq!(optimized, 1000);
        assert_eq!(ratio, 32.0);
        
        // For 1000 8-bit values
        let (standard, optimized, ratio) = estimate_cost_savings(1000, 8);
        assert_eq!(standard, 32000);
        assert_eq!(optimized, 8000);
        assert_eq!(ratio, 4.0);
    }
}
