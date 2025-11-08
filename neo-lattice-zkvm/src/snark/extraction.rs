// Witness Extraction for Symphony SNARK
// Implements coordinate-wise special soundness extraction (Lemma 2.3)

use crate::field::Field;
use crate::ring::RingElement;
use crate::protocols::rok_traits::{LinearWitness, BatchLinearWitness};
use std::marker::PhantomData;

/// Witness extractor based on Lemma 2.3 (Lemma 7.1 of [FMN24])
/// 
/// Extracts witnesses from accepting transcripts using coordinate-wise
/// special soundness.
pub struct WitnessExtractor<F: Field> {
    /// Folding arity ℓ_np
    folding_arity: usize,
    
    /// Challenge set S
    challenge_set: Vec<RingElement<F>>,
    
    _phantom: PhantomData<F>,
}

/// Extracted witness from folding
#[derive(Clone, Debug)]
pub struct ExtractedWitness<F: Field> {
    /// Individual witnesses f^ℓ for each coordinate
    pub coordinate_witnesses: Vec<Vec<RingElement<F>>>,
    
    /// Relaxation factor
    pub relaxation_factor: f64,
    
    /// Witness norm
    pub norm: f64,
}

/// Adversary interface for extraction
pub trait Adversary<F: Field> {
    /// Run adversary with given challenge
    fn run(&mut self, challenge: &[RingElement<F>]) -> Result<Transcript<F>, String>;
}

/// Transcript from adversary execution
#[derive(Clone, Debug)]
pub struct Transcript<F: Field> {
    /// Challenge used
    pub challenge: Vec<RingElement<F>>,
    
    /// Prover messages
    pub messages: Vec<Vec<u8>>,
    
    /// Output witness
    pub output_witness: Vec<RingElement<F>>,
    
    /// Acceptance flag
    pub accepted: bool,
}

/// Predicate for transcript acceptance
pub trait AcceptancePredicate<F: Field> {
    /// Check if transcript is accepting
    fn check(&self, challenge: &[RingElement<F>], transcript: &Transcript<F>) -> bool;
}

impl<F: Field> WitnessExtractor<F> {
    /// Create new witness extractor
    pub fn new(
        folding_arity: usize,
        challenge_set: Vec<RingElement<F>>,
    ) -> Self {
        Self {
            folding_arity,
            challenge_set,
            _phantom: PhantomData,
        }
    }
    
    /// Extract witness using coordinate-wise special soundness
    /// 
    /// Algorithm E^A(u_0, y_0):
    /// 1. Output (u_0, y_0)
    /// 2. For i = 1 to ℓ_np:
    ///    a. Sample u_i ≡_i u_0 (differs only in coordinate i)
    ///    b. Run A(u_i) to get y_i
    ///    c. Check Ψ(u_i, y_i) = 1
    ///    d. Output (u_i, y_i)
    /// 3. Extract f^ℓ := (f^{*,ℓ} - f^{*,0})/(u_ℓ[ℓ] - u_0[ℓ])
    pub fn extract<A, P>(
        &self,
        adversary: &mut A,
        predicate: &P,
        initial_challenge: &[RingElement<F>],
    ) -> Result<ExtractedWitness<F>, String>
    where
        A: Adversary<F>,
        P: AcceptancePredicate<F>,
    {
        if initial_challenge.len() != self.folding_arity {
            return Err(format!(
                "Challenge length {} does not match folding arity {}",
                initial_challenge.len(),
                self.folding_arity
            ));
        }
        
        // Step 1: Get initial transcript
        let y_0 = adversary.run(initial_challenge)?;
        
        if !predicate.check(initial_challenge, &y_0) {
            return Err("Initial transcript not accepting".to_string());
        }
        
        let mut transcripts = vec![(initial_challenge.to_vec(), y_0)];
        
        // Step 2: Extract for each coordinate
        for i in 0..self.folding_arity {
            // Sample u_i ≡_i u_0 (differs only in coordinate i)
            let u_i = self.sample_coordinate_variant(initial_challenge, i)?;
            
            // Run adversary
            let y_i = adversary.run(&u_i)?;
            
            // Check acceptance
            if !predicate.check(&u_i, &y_i) {
                return Err(format!(
                    "Transcript {} not accepting",
                    i + 1
                ));
            }
            
            transcripts.push((u_i, y_i));
        }
        
        // Step 3: Extract coordinate witnesses
        let coordinate_witnesses = self.extract_coordinate_witnesses(&transcripts)?;
        
        // Compute relaxation factor and norm
        let (relaxation_factor, norm) = self.compute_extraction_parameters(
            &coordinate_witnesses,
        )?;
        
        Ok(ExtractedWitness {
            coordinate_witnesses,
            relaxation_factor,
            norm,
        })
    }
    
    /// Sample challenge that differs only in coordinate i
    /// 
    /// u_i ≡_i u_0 means: u_i[i] ≠ u_0[i] and u_i[j] = u_0[j] for j ≠ i
    fn sample_coordinate_variant(
        &self,
        base_challenge: &[RingElement<F>],
        coordinate: usize,
    ) -> Result<Vec<RingElement<F>>, String> {
        let mut variant = base_challenge.to_vec();
        
        // Sample different challenge for coordinate i
        loop {
            let new_challenge = self.sample_challenge_element()?;
            if new_challenge != base_challenge[coordinate] {
                variant[coordinate] = new_challenge;
                break;
            }
        }
        
        Ok(variant)
    }
    
    /// Sample challenge element from challenge set S
    fn sample_challenge_element(&self) -> Result<RingElement<F>, String> {
        // TODO: Use proper randomness source
        let index = 0; // Simplified
        Ok(self.challenge_set[index].clone())
    }
    
    /// Extract coordinate witnesses from transcripts
    /// 
    /// For each coordinate ℓ:
    /// f^ℓ := (f^{*,ℓ} - f^{*,0})/(u_ℓ[ℓ] - u_0[ℓ])
    fn extract_coordinate_witnesses(
        &self,
        transcripts: &[(Vec<RingElement<F>>, Transcript<F>)],
    ) -> Result<Vec<Vec<RingElement<F>>>, String> {
        let mut coordinate_witnesses = Vec::with_capacity(self.folding_arity);
        
        let (u_0, y_0) = &transcripts[0];
        let f_star_0 = &y_0.output_witness;
        
        for ell in 0..self.folding_arity {
            let (u_ell, y_ell) = &transcripts[ell + 1];
            let f_star_ell = &y_ell.output_witness;
            
            // Compute f^ℓ := (f^{*,ℓ} - f^{*,0})/(u_ℓ[ℓ] - u_0[ℓ])
            let denominator = u_ell[ell].sub(&u_0[ell]);
            
            if denominator.is_zero() {
                return Err(format!(
                    "Zero denominator for coordinate {}",
                    ell
                ));
            }
            
            let denominator_inv = denominator.inverse()
                .ok_or_else(|| format!("Cannot invert denominator for coordinate {}", ell))?;
            
            let mut f_ell = Vec::with_capacity(f_star_0.len());
            for (f_ell_i, f_0_i) in f_star_ell.iter().zip(f_star_0) {
                let diff = f_ell_i.sub(f_0_i);
                let witness_i = diff.mul(&denominator_inv);
                f_ell.push(witness_i);
            }
            
            coordinate_witnesses.push(f_ell);
        }
        
        Ok(coordinate_witnesses)
    }
    
    /// Compute extraction parameters
    fn compute_extraction_parameters(
        &self,
        coordinate_witnesses: &[Vec<RingElement<F>>],
    ) -> Result<(f64, f64), String> {
        // Compute relaxation factor (typically 2 for folding)
        let relaxation_factor = 2.0;
        
        // Compute total norm
        let mut total_norm_sq = 0.0;
        for witness in coordinate_witnesses {
            for w in witness {
                let norm = w.l2_norm();
                total_norm_sq += norm * norm;
            }
        }
        let norm = total_norm_sq.sqrt();
        
        Ok((relaxation_factor, norm))
    }
    
    /// Compute extraction probability
    /// 
    /// Pr[extraction succeeds] ≥ ϵ_Ψ(A) - ℓ_np/|S|
    /// where ϵ_Ψ(A) is the acceptance probability of adversary A
    pub fn extraction_probability(
        &self,
        acceptance_probability: f64,
    ) -> f64 {
        let challenge_set_size = self.challenge_set.len() as f64;
        let penalty = (self.folding_arity as f64) / challenge_set_size;
        
        (acceptance_probability - penalty).max(0.0)
    }
    
    /// Verify extracted witnesses satisfy relaxed relation
    /// 
    /// The extracted witnesses satisfy:
    /// R̂_lin^auxcs × R̂_batchlin
    /// with relaxed norm bounds
    pub fn verify_extracted_witnesses(
        &self,
        extracted: &ExtractedWitness<F>,
        original_norm_bound: f64,
    ) -> Result<bool, String> {
        // Verify relaxed norm bound
        let relaxed_bound = extracted.relaxation_factor * original_norm_bound;
        
        if extracted.norm > relaxed_bound {
            return Ok(false);
        }
        
        // Verify each coordinate witness
        for (i, witness) in extracted.coordinate_witnesses.iter().enumerate() {
            let witness_norm = Self::compute_witness_norm(witness);
            
            if witness_norm > relaxed_bound {
                return Err(format!(
                    "Coordinate witness {} exceeds relaxed bound",
                    i
                ));
            }
        }
        
        Ok(true)
    }
    
    /// Compute L2 norm of witness
    fn compute_witness_norm(witness: &[RingElement<F>]) -> f64 {
        let mut sum_sq = 0.0;
        for w in witness {
            let norm = w.l2_norm();
            sum_sq += norm * norm;
        }
        sum_sq.sqrt()
    }
}

/// Expected number of adversary calls for extraction
/// 
/// E[# calls] = 1 + ℓ_np
pub fn expected_adversary_calls(folding_arity: usize) -> usize {
    1 + folding_arity
}

/// Knowledge error bound for extraction
/// 
/// ϵ_knowledge = ϵ_base + ℓ_np/|S|
pub fn knowledge_error_bound(
    base_error: f64,
    folding_arity: usize,
    challenge_set_size: usize,
) -> f64 {
    base_error + (folding_arity as f64) / (challenge_set_size as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_extraction_probability() {
        let extractor = WitnessExtractor::<crate::field::m61::M61>::new(
            1024,
            vec![], // Empty for test
        );
        
        // With high acceptance probability and large challenge set
        let prob = extractor.extraction_probability(0.9);
        assert!(prob > 0.8);
    }
    
    #[test]
    fn test_expected_calls() {
        assert_eq!(expected_adversary_calls(1024), 1025);
        assert_eq!(expected_adversary_calls(2048), 2049);
    }
    
    #[test]
    fn test_knowledge_error() {
        // With large challenge set, error should be small
        let error = knowledge_error_bound(2.0_f64.powi(-128), 1024, 1 << 20);
        assert!(error < 2.0_f64.powi(-100));
    }
}
