// Commitment Scheme Selection - Task 12.2
// Supports HyperKZG, Dory, HyperWolf, and Binius/FRI-Binius

use crate::field::Field;

/// Commitment scheme types
#[derive(Clone, Debug, PartialEq)]
pub enum CommitmentScheme {
    /// HyperKZG (elliptic curve based)
    HyperKZG,
    
    /// Dory (transparent, group-based)
    Dory,
    
    /// HyperWolf (lattice-based, post-quantum)
    HyperWolf,
    
    /// Binius/FRI-Binius (binary field, hashing-based)
    Binius,
}

/// Commitment scheme characteristics
#[derive(Clone, Debug)]
pub struct SchemeCharacteristics {
    /// Scheme type
    pub scheme: CommitmentScheme,
    
    /// Requires trusted setup
    pub trusted_setup: bool,
    
    /// Post-quantum secure
    pub post_quantum: bool,
    
    /// Commitment size (group elements or hash outputs)
    pub commitment_size: usize,
    
    /// Evaluation proof size (logarithmic factor)
    pub eval_proof_log_factor: usize,
    
    /// Verification time (logarithmic factor)
    pub verification_log_factor: usize,
    
    /// Best for small values
    pub optimized_for_small_values: bool,
    
    /// Best for sparse vectors
    pub optimized_for_sparsity: bool,
    
    /// Supports packing
    pub supports_packing: bool,
    
    /// Packing factor (if supported)
    pub packing_factor: usize,
}

impl SchemeCharacteristics {
    /// HyperKZG characteristics
    pub fn hyperkzg() -> Self {
        Self {
            scheme: CommitmentScheme::HyperKZG,
            trusted_setup: true,
            post_quantum: false,
            commitment_size: 1, // Single group element
            eval_proof_log_factor: 1, // O(log n)
            verification_log_factor: 1, // O(log n)
            optimized_for_small_values: true,
            optimized_for_sparsity: true,
            supports_packing: false,
            packing_factor: 1,
        }
    }
    
    /// Dory characteristics
    pub fn dory() -> Self {
        Self {
            scheme: CommitmentScheme::Dory,
            trusted_setup: false,
            post_quantum: false,
            commitment_size: 2, // √n group elements (approximated as 2 for comparison)
            eval_proof_log_factor: 1, // O(log n)
            verification_log_factor: 1, // O(log n)
            optimized_for_small_values: false,
            optimized_for_sparsity: true,
            supports_packing: false,
            packing_factor: 1,
        }
    }
    
    /// HyperWolf characteristics
    pub fn hyperwolf() -> Self {
        Self {
            scheme: CommitmentScheme::HyperWolf,
            trusted_setup: false,
            post_quantum: true,
            commitment_size: 1, // Lattice commitment
            eval_proof_log_factor: 0, // O(log log log N) with LaBRADOR (approximated as 0)
            verification_log_factor: 1, // O(log n)
            optimized_for_small_values: true,
            optimized_for_sparsity: true,
            supports_packing: false,
            packing_factor: 1,
        }
    }
    
    /// Binius characteristics
    pub fn binius() -> Self {
        Self {
            scheme: CommitmentScheme::Binius,
            trusted_setup: false,
            post_quantum: true,
            commitment_size: 1, // Hash output
            eval_proof_log_factor: 1, // O(log n)
            verification_log_factor: 1, // O(log n)
            optimized_for_small_values: false,
            optimized_for_sparsity: false,
            supports_packing: true,
            packing_factor: 128, // Pack 128 values into GF(2^128)
        }
    }
    
    /// Print characteristics
    pub fn print_characteristics(&self) {
        println!("Commitment Scheme: {:?}", self.scheme);
        println!("  Trusted setup: {}", self.trusted_setup);
        println!("  Post-quantum: {}", self.post_quantum);
        println!("  Commitment size: {} elements", self.commitment_size);
        println!("  Eval proof: O(log^{} n)", self.eval_proof_log_factor);
        println!("  Verification: O(log^{} n)", self.verification_log_factor);
        println!("  Optimized for small values: {}", self.optimized_for_small_values);
        println!("  Optimized for sparsity: {}", self.optimized_for_sparsity);
        if self.supports_packing {
            println!("  Packing factor: {}×", self.packing_factor);
        }
    }
}

/// Commitment scheme selector
pub struct CommitmentSchemeSelector;

impl CommitmentSchemeSelector {
    /// Select optimal commitment scheme based on requirements
    pub fn select(requirements: &Requirements) -> CommitmentScheme {
        // Priority 1: Post-quantum requirement
        if requirements.post_quantum_required {
            if requirements.binary_field_preferred {
                return CommitmentScheme::Binius;
            } else {
                return CommitmentScheme::HyperWolf;
            }
        }
        
        // Priority 2: No trusted setup
        if requirements.no_trusted_setup {
            if requirements.small_values_common {
                return CommitmentScheme::HyperWolf; // Also works classically
            } else {
                return CommitmentScheme::Dory;
            }
        }
        
        // Priority 3: Smallest proof size
        if requirements.minimize_proof_size {
            return CommitmentScheme::HyperKZG;
        }
        
        // Priority 4: Small values and sparsity
        if requirements.small_values_common && requirements.sparse_vectors {
            return CommitmentScheme::HyperKZG;
        }
        
        // Default: HyperKZG for best performance
        CommitmentScheme::HyperKZG
    }
    
    /// Compare all schemes for given requirements
    pub fn compare_all(requirements: &Requirements) -> Vec<(CommitmentScheme, f64)> {
        let schemes = vec![
            CommitmentScheme::HyperKZG,
            CommitmentScheme::Dory,
            CommitmentScheme::HyperWolf,
            CommitmentScheme::Binius,
        ];
        
        let mut scores = Vec::new();
        
        for scheme in schemes {
            let score = Self::score_scheme(&scheme, requirements);
            scores.push((scheme, score));
        }
        
        // Sort by score (descending)
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        
        scores
    }
    
    /// Score a scheme based on requirements (0-100)
    fn score_scheme(scheme: &CommitmentScheme, req: &Requirements) -> f64 {
        let chars = match scheme {
            CommitmentScheme::HyperKZG => SchemeCharacteristics::hyperkzg(),
            CommitmentScheme::Dory => SchemeCharacteristics::dory(),
            CommitmentScheme::HyperWolf => SchemeCharacteristics::hyperwolf(),
            CommitmentScheme::Binius => SchemeCharacteristics::binius(),
        };
        
        let mut score = 50.0; // Base score
        
        // Post-quantum requirement (critical)
        if req.post_quantum_required {
            if chars.post_quantum {
                score += 30.0;
            } else {
                return 0.0; // Disqualified
            }
        }
        
        // No trusted setup requirement (important)
        if req.no_trusted_setup {
            if !chars.trusted_setup {
                score += 20.0;
            } else {
                score -= 20.0;
            }
        }
        
        // Proof size (important)
        if req.minimize_proof_size {
            score += (5.0 - chars.commitment_size as f64) * 5.0;
        }
        
        // Small values optimization (moderate)
        if req.small_values_common && chars.optimized_for_small_values {
            score += 10.0;
        }
        
        // Sparsity optimization (moderate)
        if req.sparse_vectors && chars.optimized_for_sparsity {
            score += 10.0;
        }
        
        // Binary field preference (moderate)
        if req.binary_field_preferred && *scheme == CommitmentScheme::Binius {
            score += 15.0;
        }
        
        // Packing benefit (minor)
        if chars.supports_packing {
            score += (chars.packing_factor as f64).log2();
        }
        
        score.max(0.0).min(100.0)
    }
}

/// Requirements for commitment scheme selection
#[derive(Clone, Debug)]
pub struct Requirements {
    /// Post-quantum security required
    pub post_quantum_required: bool,
    
    /// No trusted setup allowed
    pub no_trusted_setup: bool,
    
    /// Minimize proof size
    pub minimize_proof_size: bool,
    
    /// Small values are common (32-bit, etc.)
    pub small_values_common: bool,
    
    /// Vectors are sparse
    pub sparse_vectors: bool,
    
    /// Binary field arithmetic preferred
    pub binary_field_preferred: bool,
}

impl Requirements {
    /// Default requirements (classical, trusted setup OK)
    pub fn default() -> Self {
        Self {
            post_quantum_required: false,
            no_trusted_setup: false,
            minimize_proof_size: true,
            small_values_common: true,
            sparse_vectors: true,
            binary_field_preferred: false,
        }
    }
    
    /// Post-quantum requirements
    pub fn post_quantum() -> Self {
        Self {
            post_quantum_required: true,
            no_trusted_setup: true,
            minimize_proof_size: true,
            small_values_common: true,
            sparse_vectors: true,
            binary_field_preferred: false,
        }
    }
    
    /// Transparent (no trusted setup) requirements
    pub fn transparent() -> Self {
        Self {
            post_quantum_required: false,
            no_trusted_setup: true,
            minimize_proof_size: false,
            small_values_common: false,
            sparse_vectors: false,
            binary_field_preferred: false,
        }
    }
    
    /// zkVM requirements (small values, sparsity)
    pub fn zkvm() -> Self {
        Self {
            post_quantum_required: false,
            no_trusted_setup: false,
            minimize_proof_size: true,
            small_values_common: true,
            sparse_vectors: true,
            binary_field_preferred: false,
        }
    }
}

/// Packing optimization for binary fields
pub struct PackingOptimization;

impl PackingOptimization {
    /// Compute packing factor for binary field scheme
    /// 
    /// Pack 128 values into single GF(2^128) element
    /// Achieves 128× reduction in committed elements
    pub fn compute_packing_factor(field_bits: usize, target_bits: usize) -> usize {
        target_bits / field_bits
    }
    
    /// Estimate packed commitment size
    pub fn packed_commitment_size(num_values: usize, packing_factor: usize) -> usize {
        (num_values + packing_factor - 1) / packing_factor
    }
    
    /// Print packing analysis
    pub fn print_analysis(num_values: usize) {
        println!("Packing Analysis:");
        println!("  Original values: {}", num_values);
        
        let packing_factor = 128;
        let packed_size = Self::packed_commitment_size(num_values, packing_factor);
        let reduction = num_values as f64 / packed_size as f64;
        
        println!("  Packing factor: {}×", packing_factor);
        println!("  Packed size: {}", packed_size);
        println!("  Reduction: {:.0}×", reduction);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scheme_characteristics() {
        println!("\n=== Commitment Scheme Characteristics ===\n");
        
        println!("1. HyperKZG:");
        SchemeCharacteristics::hyperkzg().print_characteristics();
        
        println!("\n2. Dory:");
        SchemeCharacteristics::dory().print_characteristics();
        
        println!("\n3. HyperWolf:");
        SchemeCharacteristics::hyperwolf().print_characteristics();
        
        println!("\n4. Binius:");
        SchemeCharacteristics::binius().print_characteristics();
    }
    
    #[test]
    fn test_scheme_selection() {
        // Test default requirements
        let req = Requirements::default();
        let scheme = CommitmentSchemeSelector::select(&req);
        assert_eq!(scheme, CommitmentScheme::HyperKZG);
        
        // Test post-quantum requirements
        let req = Requirements::post_quantum();
        let scheme = CommitmentSchemeSelector::select(&req);
        assert_eq!(scheme, CommitmentScheme::HyperWolf);
        
        // Test transparent requirements
        let req = Requirements::transparent();
        let scheme = CommitmentSchemeSelector::select(&req);
        assert_eq!(scheme, CommitmentScheme::Dory);
    }
    
    #[test]
    fn test_scheme_comparison() {
        let req = Requirements::zkvm();
        let scores = CommitmentSchemeSelector::compare_all(&req);
        
        println!("\n=== Scheme Comparison for zkVM ===\n");
        for (scheme, score) in scores {
            println!("{:?}: {:.1}/100", scheme, score);
        }
    }
    
    #[test]
    fn test_packing_optimization() {
        PackingOptimization::print_analysis(1_000_000);
        
        let packing_factor = PackingOptimization::compute_packing_factor(1, 128);
        assert_eq!(packing_factor, 128);
        
        let packed_size = PackingOptimization::packed_commitment_size(1_000_000, 128);
        assert_eq!(packed_size, 7813); // ceil(1M / 128)
    }
}
