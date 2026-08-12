// Polynomial relations for ProtogaLattice
//
// Supports general polynomial constraints including:
// - Multilinear constraints
// - High-degree polynomial constraints
// - Custom constraint systems

use crate::field::Field;
use crate::protogalattice::types::{SparseMatrix, PolynomialRelation};
use std::collections::HashMap;

/// General polynomial relation over multivariate polynomials
#[derive(Clone, Debug)]
pub struct GeneralPolynomialRelation<F: Field> {
    /// Constraints defining the relation
    pub constraints: Vec<PolynomialConstraint<F>>,
    /// Number of variables in the relation
    pub num_variables: usize,
    /// Maximum degree of any constraint
    pub max_degree: usize,
    /// Public input indices
    pub public_input_indices: Vec<usize>,
}

/// Individual polynomial constraint
#[derive(Clone, Debug)]
pub struct PolynomialConstraint<F: Field> {
    /// Terms in the constraint (each term is a product of variables)
    pub terms: Vec<ConstraintTerm<F>>,
    /// Right-hand side constant
    pub rhs: F,
    /// Label for debugging
    pub label: String,
}

/// Single term in a polynomial constraint
#[derive(Clone, Debug)]
pub struct ConstraintTerm<F: Field> {
    /// Coefficient of this term
    pub coefficient: F,
    /// Variable indices involved in this term
    pub variables: Vec<usize>,
    /// Powers of each variable
    pub powers: Vec<usize>,
}

/// Multilinear constraint (degree 1 in each variable)
#[derive(Clone, Debug)]
pub struct MultilinearConstraint<F: Field> {
    /// Coefficient matrix
    pub matrix: SparseMatrix<F>,
    /// Right-hand side vector
    pub rhs: Vec<F>,
}

/// Univariate constraint for a single variable
#[derive(Clone, Debug)]
pub struct UnivariateConstraint<F: Field> {
    /// Coefficients of the polynomial (from lowest to highest degree)
    pub coefficients: Vec<F>,
    /// Variable index
    pub variable_index: usize,
    /// Target value
    pub target: F,
}

impl<F: Field> GeneralPolynomialRelation<F> {
    /// Create new polynomial relation
    pub fn new(num_variables: usize) -> Self {
        Self {
            constraints: Vec::new(),
            num_variables,
            max_degree: 0,
            public_input_indices: Vec::new(),
        }
    }

    /// Add constraint to relation
    pub fn add_constraint(&mut self, constraint: PolynomialConstraint<F>) {
        let degree = constraint.degree();
        if degree > self.max_degree {
            self.max_degree = degree;
        }
        self.constraints.push(constraint);
    }

    /// Set public input indices
    pub fn set_public_inputs(&mut self, indices: Vec<usize>) {
        self.public_input_indices = indices;
    }

    /// Check if assignment satisfies all constraints
    pub fn is_satisfied(&self, assignment: &[F]) -> bool {
        assert_eq!(assignment.len(), self.num_variables);
        
        self.constraints.iter().all(|constraint| {
            constraint.evaluate(assignment) == constraint.rhs
        })
    }

    /// Evaluate all constraints at given assignment
    pub fn evaluate_all(&self, assignment: &[F]) -> Vec<F> {
        self.constraints
            .iter()
            .map(|c| c.evaluate(assignment))
            .collect()
    }

    /// Convert to structured form for efficient proving
    pub fn to_structured_form(&self) -> StructuredRelation<F> {
        StructuredRelation::from_general(self)
    }

    /// Get constraint by index
    pub fn get_constraint(&self, index: usize) -> Option<&PolynomialConstraint<F>> {
        self.constraints.get(index)
    }

    /// Number of constraints
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }
}

impl<F: Field> PolynomialConstraint<F> {
    /// Create new constraint
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            terms: Vec::new(),
            rhs: F::zero(),
            label: label.into(),
        }
    }

    /// Add term to constraint
    pub fn add_term(&mut self, term: ConstraintTerm<F>) {
        self.terms.push(term);
    }

    /// Set right-hand side
    pub fn set_rhs(&mut self, rhs: F) {
        self.rhs = rhs;
    }

    /// Evaluate constraint at given assignment
    pub fn evaluate(&self, assignment: &[F]) -> F {
        let mut result = F::zero();
        for term in &self.terms {
            result = result.add(&term.evaluate(assignment));
        }
        result
    }

    /// Get degree of constraint
    pub fn degree(&self) -> usize {
        self.terms
            .iter()
            .map(|t| t.total_degree())
            .max()
            .unwrap_or(0)
    }

    /// Check if constraint is linear
    pub fn is_linear(&self) -> bool {
        self.degree() <= 1
    }

    /// Check if constraint is multilinear
    pub fn is_multilinear(&self) -> bool {
        self.terms.iter().all(|t| t.is_multilinear())
    }
}

impl<F: Field> ConstraintTerm<F> {
    /// Create new term
    pub fn new(coefficient: F, variables: Vec<usize>, powers: Vec<usize>) -> Self {
        assert_eq!(variables.len(), powers.len());
        Self {
            coefficient,
            variables,
            powers,
        }
    }

    /// Create linear term (variable with power 1)
    pub fn linear(coefficient: F, variable: usize) -> Self {
        Self {
            coefficient,
            variables: vec![variable],
            powers: vec![1],
        }
    }

    /// Create constant term
    pub fn constant(coefficient: F) -> Self {
        Self {
            coefficient,
            variables: Vec::new(),
            powers: Vec::new(),
        }
    }

    /// Evaluate term at given assignment
    pub fn evaluate(&self, assignment: &[F]) -> F {
        let mut result = self.coefficient;
        
        for (&var_idx, &power) in self.variables.iter().zip(&self.powers) {
            let mut var_value = assignment[var_idx];
            for _ in 1..power {
                var_value = var_value.mul(&assignment[var_idx]);
            }
            result = result.mul(&var_value);
        }
        
        result
    }

    /// Get total degree of term
    pub fn total_degree(&self) -> usize {
        self.powers.iter().sum()
    }

    /// Check if term is multilinear
    pub fn is_multilinear(&self) -> bool {
        self.powers.iter().all(|&p| p <= 1)
    }

    /// Multiply with another term
    pub fn mul(&self, other: &Self) -> Self {
        let mut variables = Vec::new();
        let mut powers = Vec::new();
        let mut var_map: HashMap<usize, usize> = HashMap::new();

        // Add variables from self
        for (&var, &pow) in self.variables.iter().zip(&self.powers) {
            *var_map.entry(var).or_insert(0) += pow;
        }

        // Add variables from other
        for (&var, &pow) in other.variables.iter().zip(&other.powers) {
            *var_map.entry(var).or_insert(0) += pow;
        }

        // Convert map to vectors
        let mut entries: Vec<_> = var_map.into_iter().collect();
        entries.sort_by_key(|&(v, _)| v);
        
        for (var, pow) in entries {
            variables.push(var);
            powers.push(pow);
        }

        Self {
            coefficient: self.coefficient.mul(&other.coefficient),
            variables,
            powers,
        }
    }
}

impl<F: Field> MultilinearConstraint<F> {
    /// Create new multilinear constraint
    pub fn new(matrix: SparseMatrix<F>, rhs: Vec<F>) -> Self {
        assert_eq!(matrix.rows, rhs.len());
        Self { matrix, rhs }
    }

    /// Evaluate constraint
    pub fn evaluate(&self, assignment: &[F]) -> Vec<F> {
        self.matrix.mul_vec(assignment)
    }

    /// Check if satisfied
    pub fn is_satisfied(&self, assignment: &[F]) -> bool {
        let result = self.evaluate(assignment);
        result.iter().zip(&self.rhs).all(|(a, b)| a == b)
    }

    /// Convert to general polynomial constraint
    pub fn to_general(&self) -> Vec<PolynomialConstraint<F>> {
        let mut constraints = Vec::new();
        
        for row in 0..self.matrix.rows {
            let mut constraint = PolynomialConstraint::new(format!("multilinear_{}", row));
            
            for &(r, col, ref value) in &self.matrix.entries {
                if r == row {
                    let term = ConstraintTerm::linear(*value, col);
                    constraint.add_term(term);
                }
            }
            
            constraint.set_rhs(self.rhs[row]);
            constraints.push(constraint);
        }
        
        constraints
    }
}

impl<F: Field> UnivariateConstraint<F> {
    /// Create new univariate constraint
    pub fn new(coefficients: Vec<F>, variable_index: usize, target: F) -> Self {
        Self {
            coefficients,
            variable_index,
            target,
        }
    }

    /// Evaluate polynomial at variable value
    pub fn evaluate(&self, variable_value: F) -> F {
        let mut result = F::zero();
        let mut power = F::one();
        
        for coeff in &self.coefficients {
            result = result.add(&coeff.mul(&power));
            power = power.mul(&variable_value);
        }
        
        result
    }

    /// Check if satisfied for full assignment
    pub fn is_satisfied(&self, assignment: &[F]) -> bool {
        let value = self.evaluate(assignment[self.variable_index]);
        value == self.target
    }

    /// Convert to general polynomial constraint
    pub fn to_general(&self) -> PolynomialConstraint<F> {
        let mut constraint = PolynomialConstraint::new(
            format!("univariate_{}", self.variable_index)
        );
        
        for (degree, coeff) in self.coefficients.iter().enumerate() {
            if !coeff.is_zero() {
                let term = ConstraintTerm::new(
                    *coeff,
                    vec![self.variable_index],
                    vec![degree],
                );
                constraint.add_term(term);
            }
        }
        
        constraint.set_rhs(self.target);
        constraint
    }
}

/// Structured form of relation for efficient computation
#[derive(Clone, Debug)]
pub struct StructuredRelation<F: Field> {
    /// Linear part as matrix
    pub linear_part: Option<SparseMatrix<F>>,
    /// Quadratic terms
    pub quadratic_terms: Vec<QuadraticTerm<F>>,
    /// Higher degree terms
    pub higher_degree_terms: Vec<ConstraintTerm<F>>,
    /// Constants
    pub constants: Vec<F>,
    /// Number of variables
    pub num_variables: usize,
}

/// Quadratic term for efficient handling
#[derive(Clone, Debug)]
pub struct QuadraticTerm<F: Field> {
    /// Coefficient
    pub coefficient: F,
    /// First variable index
    pub var1: usize,
    /// Second variable index
    pub var2: usize,
    /// Constraint index
    pub constraint_index: usize,
}

impl<F: Field> StructuredRelation<F> {
    /// Convert from general polynomial relation
    pub fn from_general(relation: &GeneralPolynomialRelation<F>) -> Self {
        let mut linear_entries = Vec::new();
        let mut quadratic_terms = Vec::new();
        let mut higher_degree_terms = Vec::new();
        let mut constants = vec![F::zero(); relation.num_constraints()];

        for (constraint_idx, constraint) in relation.constraints.iter().enumerate() {
            for term in &constraint.terms {
                match term.total_degree() {
                    0 => {
                        // Constant term
                        constants[constraint_idx] = 
                            constants[constraint_idx].add(&term.coefficient);
                    }
                    1 => {
                        // Linear term
                        linear_entries.push((
                            constraint_idx,
                            term.variables[0],
                            term.coefficient,
                        ));
                    }
                    2 if term.variables.len() <= 2 => {
                        // Quadratic term
                        let (var1, var2) = if term.variables.len() == 1 {
                            (term.variables[0], term.variables[0])
                        } else {
                            (term.variables[0], term.variables[1])
                        };
                        
                        quadratic_terms.push(QuadraticTerm {
                            coefficient: term.coefficient,
                            var1,
                            var2,
                            constraint_index: constraint_idx,
                        });
                    }
                    _ => {
                        // Higher degree term
                        higher_degree_terms.push(term.clone());
                    }
                }
            }
            
            constants[constraint_idx] = constants[constraint_idx].sub(&constraint.rhs);
        }

        // Build linear matrix
        let linear_part = if !linear_entries.is_empty() {
            let mut matrix = SparseMatrix::new(
                relation.num_constraints(),
                relation.num_variables,
            );
            for (row, col, value) in linear_entries {
                matrix.add_entry(row, col, value);
            }
            Some(matrix)
        } else {
            None
        };

        Self {
            linear_part,
            quadratic_terms,
            higher_degree_terms,
            constants,
            num_variables: relation.num_variables,
        }
    }

    /// Evaluate structured relation
    pub fn evaluate(&self, assignment: &[F]) -> Vec<F> {
        let num_constraints = self.constants.len();
        let mut result = self.constants.clone();

        // Add linear part
        if let Some(ref linear) = self.linear_part {
            let linear_eval = linear.mul_vec(assignment);
            for (r, l) in result.iter_mut().zip(linear_eval) {
                *r = r.add(&l);
            }
        }

        // Add quadratic terms
        for term in &self.quadratic_terms {
            let val = term.coefficient
                .mul(&assignment[term.var1])
                .mul(&assignment[term.var2]);
            result[term.constraint_index] = 
                result[term.constraint_index].add(&val);
        }

        // Add higher degree terms
        for term in &self.higher_degree_terms {
            let val = term.evaluate(assignment);
            // Determine which constraint this belongs to (stored in term metadata)
            // For now, add to first constraint - this should be tracked properly
            result[0] = result[0].add(&val);
        }

        result
    }

    /// Check if satisfied
    pub fn is_satisfied(&self, assignment: &[F]) -> bool {
        let evals = self.evaluate(assignment);
        evals.iter().all(|v| v.is_zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;

    #[test]
    fn test_linear_constraint() {
        let mut matrix = SparseMatrix::new(2, 3);
        matrix.add_entry(0, 0, GoldilocksField::from(1u64));
        matrix.add_entry(0, 1, GoldilocksField::from(2u64));
        matrix.add_entry(1, 1, GoldilocksField::from(3u64));
        matrix.add_entry(1, 2, GoldilocksField::from(4u64));

        let rhs = vec![
            GoldilocksField::from(5u64),
            GoldilocksField::from(11u64),
        ];

        let constraint = MultilinearConstraint::new(matrix, rhs);

        let assignment = vec![
            GoldilocksField::from(1u64),
            GoldilocksField::from(2u64),
            GoldilocksField::from(1u64),
        ];

        assert!(constraint.is_satisfied(&assignment));
    }

    #[test]
    fn test_polynomial_constraint() {
        let mut constraint = PolynomialConstraint::new("test");
        
        // x^2 + 2*y - 3 = 0
        constraint.add_term(ConstraintTerm::new(
            GoldilocksField::from(1u64),
            vec![0],
            vec![2],
        ));
        constraint.add_term(ConstraintTerm::linear(
            GoldilocksField::from(2u64),
            1,
        ));
        constraint.set_rhs(GoldilocksField::from(3u64));

        let assignment = vec![
            GoldilocksField::from(1u64), // x = 1
            GoldilocksField::from(1u64), // y = 1
        ];

        let eval = constraint.evaluate(&assignment);
        assert_eq!(eval, constraint.rhs);
    }
}
