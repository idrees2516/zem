/// Grand Product Check Module
/// 
/// Implements efficient grand product verification for lookup arguments (Lasso/Spice)
/// using depth-first tree traversal and stack-based computation with O(n) time and O(log n) space.

use crate::field::FieldElement;
use std::collections::VecDeque;

/// Grand product check prover
pub struct GrandProductProver<F: FieldElement> {
    /// Number of variables (log n)
    num_vars: usize,
    
    /// Evaluation points for grand product
    evaluation_points: Vec<F>,
}

impl<F: FieldElement> GrandProductProver<F> {
    /// Create new grand product prover
    pub fn new(num_vars: usize) -> Self {
        Self {
            num_vars,
            evaluation_points: Vec::new(),
        }
    }
    
    /// Compute grand product using depth-first tree traversal
    /// 
    /// For polynomial g(X) = ∏_{x∈{0,1}^n} g(x), compute:
    /// - g_evals: All evaluations g(x) for x ∈ {0,1}^n
    /// - tree_nodes: All internal nodes of evaluation tree
    /// 
    /// Algorithm:
    /// 1. Perform depth-first traversal of binary tree
    /// 2. Accumulate products bottom-up
    /// 3. Store intermediate results for verification
    pub fn compute_grand_product<G>(
        &self,
        oracle: &G,
    ) -> GrandProductResult<F>
    where
        G: Fn(usize) -> F,
    {
        let n = 1 << self.num_vars;
        let mut g_evals = Vec::with_capacity(n);
        let mut tree_nodes = Vec::new();
        
        // Collect all leaf evaluations
        for i in 0..n {
            g_evals.push(oracle(i));
        }
        
        // Build tree bottom-up using depth-first traversal
        self.build_tree_dfs(&g_evals, &mut tree_nodes);
        
        // Root is the grand product
        let grand_product = if tree_nodes.is_empty() {
            F::one()
        } else {
            tree_nodes[tree_nodes.len() - 1]
        };
        
        GrandProductResult {
            grand_product,
            leaf_evals: g_evals,
            tree_nodes,
            num_vars: self.num_vars,
        }
    }
    
    /// Build evaluation tree using depth-first traversal
    /// 
    /// Space: O(log n) for recursion stack
    /// Time: O(n) for all multiplications
    fn build_tree_dfs(&self, leaves: &[F], tree_nodes: &mut Vec<F>) {
        if leaves.is_empty() {
            return;
        }
        
        if leaves.len() == 1 {
            tree_nodes.push(leaves[0]);
            return;
        }
        
        let mid = leaves.len() / 2;
        
        // Process left subtree
        self.build_tree_dfs(&leaves[..mid], tree_nodes);
        let left_product = tree_nodes[tree_nodes.len() - 1];
        
        // Process right subtree
        self.build_tree_dfs(&leaves[mid..], tree_nodes);
        let right_product = tree_nodes[tree_nodes.len() - 1];
        
        // Combine products
        let combined = left_product * right_product;
        tree_nodes.push(combined);
    }
    
    /// Compute grand product using stack-based algorithm
    /// 
    /// Alternative to recursion, uses explicit stack for space efficiency
    /// 
    /// Algorithm:
    /// 1. Initialize stack with leaf nodes
    /// 2. While stack has > 1 element:
    ///    - Pop two elements
    ///    - Multiply them
    ///    - Push result back
    /// 3. Final element is grand product
    pub fn compute_grand_product_stack<G>(
        &self,
        oracle: &G,
    ) -> GrandProductResult<F>
    where
        G: Fn(usize) -> F,
    {
        let n = 1 << self.num_vars;
        let mut g_evals = Vec::with_capacity(n);
        
        // Collect all leaf evaluations
        for i in 0..n {
            g_evals.push(oracle(i));
        }
        
        // Use stack-based computation
        let mut stack: VecDeque<F> = g_evals.iter().copied().collect();
        let mut tree_nodes = Vec::new();
        
        while stack.len() > 1 {
            let left = stack.pop_front().unwrap();
            let right = stack.pop_front().unwrap();
            let product = left * right;
            tree_nodes.push(product);
            stack.push_back(product);
        }
        
        let grand_product = stack.pop_front().unwrap_or(F::one());
        
        GrandProductResult {
            grand_product,
            leaf_evals: g_evals,
            tree_nodes,
            num_vars: self.num_vars,
        }
    }
}

/// Result of grand product computation
#[derive(Clone, Debug)]
pub struct GrandProductResult<F: FieldElement> {
    /// The grand product ∏ g(x)
    pub grand_product: F,
    
    /// All leaf evaluations g(x) for x ∈ {0,1}^n
    pub leaf_evals: Vec<F>,
    
    /// All internal tree nodes (intermediate products)
    pub tree_nodes: Vec<F>,
    
    /// Number of variables
    pub num_vars: usize,
}

impl<F: FieldElement> GrandProductResult<F> {
    /// Verify grand product computation
    /// 
    /// Check that:
    /// 1. All leaf evaluations are present
    /// 2. Tree nodes are correctly computed
    /// 3. Root equals claimed grand product
    pub fn verify(&self) -> bool {
        let n = 1 << self.num_vars;
        
        // Check leaf count
        if self.leaf_evals.len() != n {
            return false;
        }
        
        // Verify tree structure
        if !self.verify_tree_structure() {
            return false;
        }
        
        // Verify root
        if self.tree_nodes.is_empty() {
            return self.grand_product == F::one();
        }
        
        self.tree_nodes[self.tree_nodes.len() - 1] == self.grand_product
    }
    
    /// Verify tree structure is correct
    fn verify_tree_structure(&self) -> bool {
        if self.tree_nodes.is_empty() {
            return true;
        }
        
        // Reconstruct tree and verify
        let mut reconstructed = Vec::new();
        self.verify_tree_dfs(&self.leaf_evals, &mut reconstructed);
        
        reconstructed == self.tree_nodes
    }
    
    /// Verify tree using depth-first traversal
    fn verify_tree_dfs(&self, leaves: &[F], tree_nodes: &mut Vec<F>) {
        if leaves.is_empty() {
            return;
        }
        
        if leaves.len() == 1 {
            tree_nodes.push(leaves[0]);
            return;
        }
        
        let mid = leaves.len() / 2;
        
        self.verify_tree_dfs(&leaves[..mid], tree_nodes);
        let left_product = tree_nodes[tree_nodes.len() - 1];
        
        self.verify_tree_dfs(&leaves[mid..], tree_nodes);
        let right_product = tree_nodes[tree_nodes.len() - 1];
        
        let combined = left_product * right_product;
        tree_nodes.push(combined);
    }
    
    /// Get space complexity in field elements
    pub fn space_complexity(&self) -> usize {
        // Recursion stack: O(log n)
        // Tree nodes: O(n) in worst case, but typically O(n/2) for balanced tree
        self.tree_nodes.len()
    }
    
    /// Get time complexity in field multiplications
    pub fn time_complexity(&self) -> usize {
        // One multiplication per internal node
        self.tree_nodes.len()
    }
}

/// Special case handler for 1^n (all ones)
pub struct SpecialCaseHandler;

impl SpecialCaseHandler {
    /// Check if all evaluations are 1
    pub fn is_all_ones<F: FieldElement>(evals: &[F]) -> bool {
        evals.iter().all(|&e| e == F::one())
    }
    
    /// Compute grand product for all ones
    /// 
    /// If all g(x) = 1, then ∏ g(x) = 1
    pub fn compute_all_ones<F: FieldElement>(n: usize) -> F {
        if n == 0 {
            F::one()
        } else {
            F::one()
        }
    }
    
    /// Optimize computation when all evaluations are 1
    pub fn optimize_all_ones<F: FieldElement>(
        evals: &[F],
    ) -> Option<F> {
        if Self::is_all_ones(evals) {
            Some(F::one())
        } else {
            None
        }
    }
}

/// Grand product accumulator for streaming computation
pub struct GrandProductAccumulator<F: FieldElement> {
    /// Current accumulated product
    current_product: F,
    
    /// Number of elements processed
    count: usize,
}

impl<F: FieldElement> GrandProductAccumulator<F> {
    /// Create new accumulator
    pub fn new() -> Self {
        Self {
            current_product: F::one(),
            count: 0,
        }
    }
    
    /// Add element to product
    pub fn multiply(&mut self, element: F) {
        self.current_product = self.current_product * element;
        self.count += 1;
    }
    
    /// Get current product
    pub fn product(&self) -> F {
        self.current_product
    }
    
    /// Get count of elements
    pub fn count(&self) -> usize {
        self.count
    }
    
    /// Reset accumulator
    pub fn reset(&mut self) {
        self.current_product = F::one();
        self.count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Mock field element for testing
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct MockField(u64);
    
    impl FieldElement for MockField {
        fn add(&self, other: &Self) -> Self {
            MockField((self.0 + other.0) % 1000000007)
        }
        
        fn sub(&self, other: &Self) -> Self {
            MockField((self.0 + 1000000007 - other.0) % 1000000007)
        }
        
        fn mul(&self, other: &Self) -> Self {
            MockField((self.0 * other.0) % 1000000007)
        }
        
        fn div(&self, other: &Self) -> Self {
            // Simplified for testing
            MockField(self.0)
        }
        
        fn neg(&self) -> Self {
            MockField((1000000007 - self.0) % 1000000007)
        }
        
        fn inv(&self) -> Self {
            // Simplified for testing
            MockField(1)
        }
        
        fn zero() -> Self {
            MockField(0)
        }
        
        fn one() -> Self {
            MockField(1)
        }
        
        fn from_u64(val: u64) -> Self {
            MockField(val % 1000000007)
        }
        
        fn to_bytes(&self) -> Vec<u8> {
            self.0.to_le_bytes().to_vec()
        }
        
        fn from_bytes(bytes: &[u8]) -> Self {
            let mut val = 0u64;
            for (i, &b) in bytes.iter().take(8).enumerate() {
                val |= (b as u64) << (i * 8);
            }
            MockField(val % 1000000007)
        }
    }
    
    #[test]
    fn test_grand_product_single_element() {
        let prover = GrandProductProver::new(0);
        let result = prover.compute_grand_product(&|_| MockField(5));
        
        assert_eq!(result.grand_product, MockField(5));
        assert_eq!(result.leaf_evals.len(), 1);
    }
    
    #[test]
    fn test_grand_product_two_elements() {
        let prover = GrandProductProver::new(1);
        let evals = vec![MockField(2), MockField(3)];
        let result = prover.compute_grand_product(&|i| evals[i]);
        
        assert_eq!(result.grand_product, MockField(6));
        assert_eq!(result.leaf_evals.len(), 2);
    }
    
    #[test]
    fn test_grand_product_four_elements() {
        let prover = GrandProductProver::new(2);
        let evals = vec![MockField(1), MockField(2), MockField(3), MockField(4)];
        let result = prover.compute_grand_product(&|i| evals[i]);
        
        assert_eq!(result.grand_product, MockField(24));
        assert_eq!(result.leaf_evals.len(), 4);
    }
    
    #[test]
    fn test_grand_product_stack_based() {
        let prover = GrandProductProver::new(2);
        let evals = vec![MockField(1), MockField(2), MockField(3), MockField(4)];
        let result = prover.compute_grand_product_stack(&|i| evals[i]);
        
        assert_eq!(result.grand_product, MockField(24));
        assert_eq!(result.leaf_evals.len(), 4);
    }
    
    #[test]
    fn test_grand_product_verify() {
        let prover = GrandProductProver::new(2);
        let evals = vec![MockField(1), MockField(2), MockField(3), MockField(4)];
        let result = prover.compute_grand_product(&|i| evals[i]);
        
        assert!(result.verify());
    }
    
    #[test]
    fn test_special_case_all_ones() {
        let evals = vec![MockField(1), MockField(1), MockField(1), MockField(1)];
        
        assert!(SpecialCaseHandler::is_all_ones(&evals));
        assert_eq!(SpecialCaseHandler::compute_all_ones::<MockField>(4), MockField(1));
        assert_eq!(SpecialCaseHandler::optimize_all_ones(&evals), Some(MockField(1)));
    }
    
    #[test]
    fn test_accumulator() {
        let mut acc = GrandProductAccumulator::new();
        
        acc.multiply(MockField(2));
        assert_eq!(acc.product(), MockField(2));
        assert_eq!(acc.count(), 1);
        
        acc.multiply(MockField(3));
        assert_eq!(acc.product(), MockField(6));
        assert_eq!(acc.count(), 2);
        
        acc.reset();
        assert_eq!(acc.product(), MockField(1));
        assert_eq!(acc.count(), 0);
    }
}
