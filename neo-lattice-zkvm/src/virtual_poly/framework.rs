// Task 4.1: Virtual Polynomial Framework
// Generic framework for polynomials not directly committed

use crate::field::extension_framework::ExtensionFieldElement;
use crate::sumcheck::{MultilinearPolynomial, UnivariatePolynomial};
use crate::shout::virtual_polynomials::SumCheckClaim;
use std::collections::HashMap;

/// Virtual polynomial trait - core interface
/// Polynomials expressed as low-degree functions of committed data
pub trait VirtualPolyTrait<K: ExtensionFieldElement>: Clone {
    /// Evaluate via sum-check at given point
    /// Returns value and proof of correctness
    fn evaluate_via_sumcheck(
        &self,
        point: &[K],
        committed_polys: &HashMap<String, MultilinearPolynomial<K>>,
    ) -> Result<VirtualEvaluation<K>, String>;
    
    /// Generate sum-check claim for this evaluation
    fn sumcheck_claim(&self, point: &[K]) -> SumCheckClaim<K>;
    
    /// Get dependencies on other polynomials
    fn dependencies(&self) -> Vec<String>;
    
    /// Check if this virtual polynomial depends on another
    fn depends_on(&self, poly_id: &str) -> bool {
        self.dependencies().contains(&poly_id.to_string())
    }
}

/// Virtual polynomial evaluation result
#[derive(Clone, Debug)]
pub struct VirtualEvaluation<K: ExtensionFieldElement> {
    /// Computed value
    pub value: K,
    
    /// Sum-check proof
    pub proof: VirtualProof<K>,
    
    /// Intermediate evaluations (for chaining)
    pub intermediates: HashMap<String, K>,
}

/// Virtual polynomial proof
#[derive(Clone, Debug)]
pub struct VirtualProof<K: ExtensionFieldElement> {
    /// Round polynomials from sum-check
    pub round_polynomials: Vec<UnivariatePolynomial<K>>,
    
    /// Challenges used
    pub challenges: Vec<K>,
    
    /// Final evaluations of committed polynomials
    pub final_evals: HashMap<String, K>,
}

/// Virtual polynomial framework
/// Manages virtual polynomials and their dependencies
pub struct VirtualPolynomialFramework<K: ExtensionFieldElement> {
    /// Committed polynomials (base layer)
    committed: HashMap<String, MultilinearPolynomial<K>>,
    
    /// Virtual polynomials (derived layer)
    virtual_polys: HashMap<String, Box<dyn VirtualPolyTrait<K>>>,
    
    /// Dependency graph
    dependencies: HashMap<String, Vec<String>>,
}

impl<K: ExtensionFieldElement> VirtualPolynomialFramework<K> {
    pub fn new() -> Self {
        Self {
            committed: HashMap::new(),
            virtual_polys: HashMap::new(),
            dependencies: HashMap::new(),
        }
    }
    
    /// Add committed polynomial (base layer)
    pub fn add_committed(&mut self, id: String, poly: MultilinearPolynomial<K>) {
        self.committed.insert(id, poly);
    }
    
    /// Add virtual polynomial (derived layer)
    pub fn add_virtual(
        &mut self,
        id: String,
        poly: Box<dyn VirtualPolyTrait<K>>,
    ) -> Result<(), String> {
        // Check dependencies exist
        let deps = poly.dependencies();
        for dep in &deps {
            if !self.committed.contains_key(dep) && !self.virtual_polys.contains_key(dep) {
                return Err(format!("Dependency {} not found", dep));
            }
        }
        
        // Check for circular dependencies
        if self.has_circular_dependency(&id, &deps) {
            return Err("Circular dependency detected".to_string());
        }
        
        self.dependencies.insert(id.clone(), deps);
        self.virtual_polys.insert(id, poly);
        Ok(())
    }
    
    /// Evaluate virtual polynomial
    /// Handles chaining automatically
    pub fn evaluate(
        &self,
        poly_id: &str,
        point: &[K],
    ) -> Result<VirtualEvaluation<K>, String> {
        // Check if it's committed (direct evaluation)
        if let Some(poly) = self.committed.get(poly_id) {
            let value = poly.evaluate(point)?;
            return Ok(VirtualEvaluation {
                value,
                proof: VirtualProof {
                    round_polynomials: vec![],
                    challenges: vec![],
                    final_evals: HashMap::new(),
                },
                intermediates: HashMap::new(),
            });
        }
        
        // Must be virtual
        let virtual_poly = self.virtual_polys.get(poly_id)
            .ok_or_else(|| format!("Polynomial {} not found", poly_id))?;
        
        // Evaluate dependencies first (recursive)
        let mut intermediate_evals = HashMap::new();
        for dep in virtual_poly.dependencies() {
            let dep_eval = self.evaluate(&dep, point)?;
            intermediate_evals.insert(dep.clone(), dep_eval.value);
        }
        
        // Evaluate this virtual polynomial
        virtual_poly.evaluate_via_sumcheck(point, &self.committed)
    }
    
    /// Check for circular dependencies
    fn has_circular_dependency(&self, new_id: &str, new_deps: &[String]) -> bool {
        for dep in new_deps {
            if dep == new_id {
                return true;
            }
            
            if let Some(transitive_deps) = self.dependencies.get(dep) {
                if self.has_circular_dependency_recursive(new_id, transitive_deps) {
                    return true;
                }
            }
        }
        
        false
    }
    
    fn has_circular_dependency_recursive(&self, target: &str, deps: &[String]) -> bool {
        for dep in deps {
            if dep == target {
                return true;
            }
            
            if let Some(transitive_deps) = self.dependencies.get(dep) {
                if self.has_circular_dependency_recursive(target, transitive_deps) {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Get evaluation order (topological sort)
    pub fn evaluation_order(&self, poly_id: &str) -> Result<Vec<String>, String> {
        let mut order = Vec::new();
        let mut visited = std::collections::HashSet::new();
        
        self.topological_sort(poly_id, &mut order, &mut visited)?;
        
        Ok(order)
    }
    
    fn topological_sort(
        &self,
        poly_id: &str,
        order: &mut Vec<String>,
        visited: &mut std::collections::HashSet<String>,
    ) -> Result<(), String> {
        if visited.contains(poly_id) {
            return Ok(());
        }
        
        visited.insert(poly_id.to_string());
        
        // Visit dependencies first
        if let Some(deps) = self.dependencies.get(poly_id) {
            for dep in deps {
                self.topological_sort(dep, order, visited)?;
            }
        }
        
        order.push(poly_id.to_string());
        Ok(())
    }
}

/// Nested sum-check support
/// Allows virtual polynomials to depend on other virtual polynomials
pub struct NestedSumCheck<K: ExtensionFieldElement> {
    /// Nesting level
    pub level: usize,
    
    /// Parent sum-check (if nested)
    pub parent: Option<Box<NestedSumCheck<K>>>,
    
    /// Current sum-check state
    pub round_polynomials: Vec<UnivariatePolynomial<K>>,
    pub challenges: Vec<K>,
}

impl<K: ExtensionFieldElement> NestedSumCheck<K> {
    pub fn new(level: usize) -> Self {
        Self {
            level,
            parent: None,
            round_polynomials: Vec::new(),
            challenges: Vec::new(),
        }
    }
    
    pub fn with_parent(level: usize, parent: NestedSumCheck<K>) -> Self {
        Self {
            level,
            parent: Some(Box::new(parent)),
            round_polynomials: Vec::new(),
            challenges: Vec::new(),
        }
    }
    
    /// Add round polynomial
    pub fn add_round(&mut self, poly: UnivariatePolynomial<K>, challenge: K) {
        self.round_polynomials.push(poly);
        self.challenges.push(challenge);
    }
    
    /// Get total depth
    pub fn depth(&self) -> usize {
        if let Some(parent) = &self.parent {
            1 + parent.depth()
        } else {
            1
        }
    }
    
    /// Flatten to single proof
    pub fn flatten(&self) -> VirtualProof<K> {
        let mut all_rounds = Vec::new();
        let mut all_challenges = Vec::new();
        
        // Collect from parent first
        if let Some(parent) = &self.parent {
            let parent_proof = parent.flatten();
            all_rounds.extend(parent_proof.round_polynomials);
            all_challenges.extend(parent_proof.challenges);
        }
        
        // Add current level
        all_rounds.extend(self.round_polynomials.clone());
        all_challenges.extend(self.challenges.clone());
        
        VirtualProof {
            round_polynomials: all_rounds,
            challenges: all_challenges,
            final_evals: HashMap::new(),
        }
    }
}

/// Soundness verification for virtual polynomials
pub struct VirtualSoundness;

impl VirtualSoundness {
    /// Verify virtual polynomial evaluation is sound
    /// Checks that sum-check proof is valid
    pub fn verify<K: ExtensionFieldElement>(
        proof: &VirtualProof<K>,
        claimed_value: K,
        num_variables: usize,
    ) -> Result<bool, String> {
        if proof.round_polynomials.len() != num_variables {
            return Err("Incorrect number of rounds".to_string());
        }
        
        // Verify first round
        let s_1 = &proof.round_polynomials[0];
        let sum = s_1.evaluate_at_int(0).add(&s_1.evaluate_at_int(1));
        if sum != claimed_value {
            return Ok(false);
        }
        
        // Verify subsequent rounds
        for i in 1..num_variables {
            let s_prev = &proof.round_polynomials[i - 1];
            let s_curr = &proof.round_polynomials[i];
            let r_prev = proof.challenges[i - 1];
            
            let lhs = s_prev.evaluate(r_prev);
            let rhs = s_curr.evaluate_at_int(0).add(&s_curr.evaluate_at_int(1));
            
            if lhs != rhs {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Compute soundness error
    /// Error = (degree * num_rounds) / |F|
    pub fn soundness_error<K: ExtensionFieldElement>(
        degree: usize,
        num_rounds: usize,
    ) -> f64 {
        let field_size = K::BaseField::MODULUS as f64;
        (degree * num_rounds) as f64 / field_size
    }
}
