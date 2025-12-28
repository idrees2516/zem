// Plonkish Constraint System
// Implements f(q(X), w(X)) = 0 with selector polynomials
//
// Paper Reference: PLONK paper and various Plonkish arithmetization papers
// Also: "Sum-check Is All You Need" (2025-2041), Section 5.3
//
// This module implements the Plonkish constraint system, which is a more
// flexible alternative to R1CS that supports custom gates and lookup tables.
//
// Mathematical Background:
// Plonkish represents computations using:
// - Witness polynomials: w_1(X), ..., w_k(X)
// - Selector polynomials: q_1(X), ..., q_m(X)
// - Custom gate constraints: f(q(X), w(X)) = 0
//
// Key Differences from R1CS:
// 1. Custom gates: Can express complex operations in single constraint
// 2. Lookup tables: Efficient range checks and table lookups
// 3. Copy constraints: Enforce equality between wire values
// 4. Permutation arguments: Verify wire connections
//
// Gate Structure:
// Each gate is defined by a polynomial constraint:
// q_L(X)·w_a(X) + q_R(X)·w_b(X) + q_O(X)·w_c(X) + q_M(X)·w_a(X)·w_b(X) + q_C(X) = 0
//
// where:
// - q_L, q_R, q_O are linear selectors
// - q_M is multiplication selector
// - q_C is constant selector
// - w_a, w_b, w_c are witness wires
//
// This allows encoding:
// - Addition: q_L=1, q_R=1, q_O=-1, others=0 → a + b = c
// - Multiplication: q_M=1, q_O=-1, others=0 → a·b = c
// - Constants: q_C=k, q_O=-1, others=0 → k = c
//
// Lookup Tables:
// Paper Reference: PLOOKUP paper
//
// For efficient range checks and table lookups, Plonkish supports:
// - Table polynomial t(X) encoding allowed values
// - Lookup argument proving w(X) ∈ t(X)
// - Multiset equality check via permutation
//
// This is much more efficient than bit decomposition for range checks.
//
// Copy Constraints:
// To enforce that wire values are equal across gates, we use:
// - Permutation polynomial σ(X)
// - Grand product argument
// - Proves w_i(g_j) = w_k(g_l) for specified wire connections
//
// This allows wiring gates together without explicit equality constraints.

use crate::field::Field;
use crate::polynomial::MultilinearPolynomial;
use std::collections::HashMap;

/// Plonkish gate type
///
/// Defines the type of gate and its selector values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateType {
    /// Addition gate: a + b = c
    Addition,
    
    /// Multiplication gate: a · b = c
    Multiplication,
    
    /// Constant gate: k = c
    Constant,
    
    /// Custom gate with specific selectors
    Custom {
        q_l: i64,
        q_r: i64,
        q_o: i64,
        q_m: i64,
        q_c: i64,
    },
}

/// Plonkish gate
///
/// Represents a single gate in the circuit.
#[derive(Clone, Debug)]
pub struct PlonkishGate<F: Field> {
    /// Gate type
    pub gate_type: GateType,
    
    /// Left wire index
    pub wire_a: usize,
    
    /// Right wire index
    pub wire_b: usize,
    
    /// Output wire index
    pub wire_c: usize,
    
    /// Constant value (for constant gates)
    pub constant: Option<F>,
}

impl<F: Field> PlonkishGate<F> {
    /// Create addition gate: a + b = c
    pub fn addition(wire_a: usize, wire_b: usize, wire_c: usize) -> Self {
        Self {
            gate_type: GateType::Addition,
            wire_a,
            wire_b,
            wire_c,
            constant: None,
        }
    }
    
    /// Create multiplication gate: a · b = c
    pub fn multiplication(wire_a: usize, wire_b: usize, wire_c: usize) -> Self {
        Self {
            gate_type: GateType::Multiplication,
            wire_a,
            wire_b,
            wire_c,
            constant: None,
        }
    }
    
    /// Create constant gate: k = c
    pub fn constant(constant: F, wire_c: usize) -> Self {
        Self {
            gate_type: GateType::Constant,
            wire_a: 0,
            wire_b: 0,
            wire_c,
            constant: Some(constant),
        }
    }
    
    /// Create custom gate with specific selectors
    pub fn custom(
        q_l: i64,
        q_r: i64,
        q_o: i64,
        q_m: i64,
        q_c: i64,
        wire_a: usize,
        wire_b: usize,
        wire_c: usize,
    ) -> Self {
        Self {
            gate_type: GateType::Custom { q_l, q_r, q_o, q_m, q_c },
            wire_a,
            wire_b,
            wire_c,
            constant: None,
        }
    }
    
    /// Get selector values for this gate
    ///
    /// Returns (q_L, q_R, q_O, q_M, q_C)
    pub fn selectors(&self) -> (F, F, F, F, F) {
        match &self.gate_type {
            GateType::Addition => {
                // a + b = c → q_L=1, q_R=1, q_O=-1
                (F::one(), F::one(), F::zero().sub(&F::one()), F::zero(), F::zero())
            }
            GateType::Multiplication => {
                // a·b = c → q_M=1, q_O=-1
                (F::zero(), F::zero(), F::zero().sub(&F::one()), F::one(), F::zero())
            }
            GateType::Constant => {
                // k = c → q_C=k, q_O=-1
                let k = self.constant.unwrap_or(F::zero());
                (F::zero(), F::zero(), F::zero().sub(&F::one()), F::zero(), k)
            }
            GateType::Custom { q_l, q_r, q_o, q_m, q_c } => {
                (
                    F::from_u64(*q_l as u64),
                    F::from_u64(*q_r as u64),
                    F::from_u64(*q_o as u64),
                    F::from_u64(*q_m as u64),
                    F::from_u64(*q_c as u64),
                )
            }
        }
    }
    
    /// Evaluate gate constraint
    ///
    /// Computes: q_L·a + q_R·b + q_O·c + q_M·a·b + q_C
    ///
    /// Should equal zero if constraint is satisfied.
    pub fn evaluate(&self, wire_values: &[F]) -> F {
        let a = wire_values[self.wire_a];
        let b = wire_values[self.wire_b];
        let c = wire_values[self.wire_c];
        
        let (q_l, q_r, q_o, q_m, q_c) = self.selectors();
        
        // q_L·a + q_R·b + q_O·c + q_M·a·b + q_C
        q_l.mul(&a)
            .add(&q_r.mul(&b))
            .add(&q_o.mul(&c))
            .add(&q_m.mul(&a).mul(&b))
            .add(&q_c)
    }
}

/// Copy constraint
///
/// Enforces that two wire values are equal.
#[derive(Clone, Debug)]
pub struct CopyConstraint {
    /// First wire index
    pub wire_1: usize,
    
    /// Second wire index
    pub wire_2: usize,
}

impl CopyConstraint {
    /// Create new copy constraint
    pub fn new(wire_1: usize, wire_2: usize) -> Self {
        Self { wire_1, wire_2 }
    }
    
    /// Verify copy constraint
    pub fn verify<F: Field>(&self, wire_values: &[F]) -> bool {
        if self.wire_1 >= wire_values.len() || self.wire_2 >= wire_values.len() {
            return false;
        }
        
        wire_values[self.wire_1].to_canonical_u64() == wire_values[self.wire_2].to_canonical_u64()
    }
}

/// Lookup table
///
/// Paper Reference: PLOOKUP paper
///
/// Represents a table of allowed values for efficient lookups.
#[derive(Clone, Debug)]
pub struct LookupTable<F: Field> {
    /// Table name
    pub name: String,
    
    /// Table values
    pub values: Vec<F>,
    
    /// Number of columns (for multi-column tables)
    pub num_columns: usize,
}

impl<F: Field> LookupTable<F> {
    /// Create new lookup table
    pub fn new(name: String, values: Vec<F>, num_columns: usize) -> Self {
        Self {
            name,
            values,
            num_columns,
        }
    }
    
    /// Create range table for values in [0, 2^k)
    ///
    /// This is useful for range checks without bit decomposition.
    pub fn range_table(k: usize) -> Self {
        let size = 1 << k;
        let values: Vec<F> = (0..size)
            .map(|i| F::from_u64(i as u64))
            .collect();
        
        Self::new(format!("range_{}", k), values, 1)
    }
    
    /// Check if value is in table
    pub fn contains(&self, value: F) -> bool {
        self.values.iter().any(|v| v.to_canonical_u64() == value.to_canonical_u64())
    }
    
    /// Get table polynomial
    ///
    /// Returns multilinear extension of table values.
    pub fn to_polynomial(&self) -> Result<MultilinearPolynomial<F>, String> {
        // Pad to power of 2
        let mut padded = self.values.clone();
        let target_size = padded.len().next_power_of_two();
        padded.resize(target_size, F::zero());
        
        MultilinearPolynomial::from_evaluations(padded)
    }
}

/// Lookup constraint
///
/// Proves that a wire value is in a lookup table.
#[derive(Clone, Debug)]
pub struct LookupConstraint {
    /// Wire index to lookup
    pub wire: usize,
    
    /// Table name
    pub table_name: String,
}

impl LookupConstraint {
    /// Create new lookup constraint
    pub fn new(wire: usize, table_name: String) -> Self {
        Self { wire, table_name }
    }
    
    /// Verify lookup constraint
    pub fn verify<F: Field>(&self, wire_values: &[F], tables: &HashMap<String, LookupTable<F>>) -> bool {
        if self.wire >= wire_values.len() {
            return false;
        }
        
        if let Some(table) = tables.get(&self.table_name) {
            table.contains(wire_values[self.wire])
        } else {
            false
        }
    }
}

/// Plonkish constraint system
///
/// Paper Reference: PLONK and Plonkish papers
///
/// Complete constraint system with gates, copy constraints, and lookups.
#[derive(Clone, Debug)]
pub struct PlonkishCircuit<F: Field> {
    /// Gates in the circuit
    pub gates: Vec<PlonkishGate<F>>,
    
    /// Copy constraints
    pub copy_constraints: Vec<CopyConstraint>,
    
    /// Lookup constraints
    pub lookup_constraints: Vec<LookupConstraint>,
    
    /// Lookup tables
    pub lookup_tables: HashMap<String, LookupTable<F>>,
    
    /// Number of wires
    pub num_wires: usize,
    
    /// Number of public inputs
    pub num_public_inputs: usize,
}

impl<F: Field> PlonkishCircuit<F> {
    /// Create new Plonkish circuit
    pub fn new(num_wires: usize, num_public_inputs: usize) -> Self {
        Self {
            gates: Vec::new(),
            copy_constraints: Vec::new(),
            lookup_constraints: Vec::new(),
            lookup_tables: HashMap::new(),
            num_wires,
            num_public_inputs,
        }
    }
    
    /// Add gate to circuit
    pub fn add_gate(&mut self, gate: PlonkishGate<F>) {
        self.gates.push(gate);
    }
    
    /// Add copy constraint
    pub fn add_copy_constraint(&mut self, wire_1: usize, wire_2: usize) {
        self.copy_constraints.push(CopyConstraint::new(wire_1, wire_2));
    }
    
    /// Add lookup table
    pub fn add_lookup_table(&mut self, table: LookupTable<F>) {
        self.lookup_tables.insert(table.name.clone(), table);
    }
    
    /// Add lookup constraint
    pub fn add_lookup_constraint(&mut self, wire: usize, table_name: String) {
        self.lookup_constraints.push(LookupConstraint::new(wire, table_name));
    }
    
    /// Verify circuit with witness
    ///
    /// Paper Reference: PLONK verification
    ///
    /// Checks all constraints:
    /// 1. Gate constraints: f(q, w) = 0
    /// 2. Copy constraints: w_i = w_j
    /// 3. Lookup constraints: w_i ∈ table
    pub fn verify(&self, wire_values: &[F]) -> Result<bool, String> {
        if wire_values.len() != self.num_wires {
            return Err(format!(
                "Wire values length {} doesn't match circuit wires {}",
                wire_values.len(), self.num_wires
            ));
        }
        
        // Verify gate constraints
        for (i, gate) in self.gates.iter().enumerate() {
            let result = gate.evaluate(wire_values);
            if result.to_canonical_u64() != 0 {
                return Ok(false);
            }
        }
        
        // Verify copy constraints
        for constraint in &self.copy_constraints {
            if !constraint.verify(wire_values) {
                return Ok(false);
            }
        }
        
        // Verify lookup constraints
        for constraint in &self.lookup_constraints {
            if !constraint.verify(wire_values, &self.lookup_tables) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Convert to selector polynomials
    ///
    /// Paper Reference: PLONK polynomial encoding
    ///
    /// Creates selector polynomials q_L(X), q_R(X), q_O(X), q_M(X), q_C(X)
    /// where each polynomial encodes the selectors for all gates.
    pub fn to_selector_polynomials(&self) -> Result<(
        MultilinearPolynomial<F>,
        MultilinearPolynomial<F>,
        MultilinearPolynomial<F>,
        MultilinearPolynomial<F>,
        MultilinearPolynomial<F>,
    ), String> {
        let num_gates = self.gates.len();
        let padded_size = num_gates.next_power_of_two();
        
        let mut q_l_vals = Vec::with_capacity(padded_size);
        let mut q_r_vals = Vec::with_capacity(padded_size);
        let mut q_o_vals = Vec::with_capacity(padded_size);
        let mut q_m_vals = Vec::with_capacity(padded_size);
        let mut q_c_vals = Vec::with_capacity(padded_size);
        
        for gate in &self.gates {
            let (q_l, q_r, q_o, q_m, q_c) = gate.selectors();
            q_l_vals.push(q_l);
            q_r_vals.push(q_r);
            q_o_vals.push(q_o);
            q_m_vals.push(q_m);
            q_c_vals.push(q_c);
        }
        
        // Pad to power of 2
        q_l_vals.resize(padded_size, F::zero());
        q_r_vals.resize(padded_size, F::zero());
        q_o_vals.resize(padded_size, F::zero());
        q_m_vals.resize(padded_size, F::zero());
        q_c_vals.resize(padded_size, F::zero());
        
        Ok((
            MultilinearPolynomial::from_evaluations(q_l_vals)?,
            MultilinearPolynomial::from_evaluations(q_r_vals)?,
            MultilinearPolynomial::from_evaluations(q_o_vals)?,
            MultilinearPolynomial::from_evaluations(q_m_vals)?,
            MultilinearPolynomial::from_evaluations(q_c_vals)?,
        ))
    }
    
    /// Convert wire values to polynomials
    ///
    /// Creates witness polynomials w_a(X), w_b(X), w_c(X)
    pub fn wire_values_to_polynomials(&self, wire_values: &[F]) -> Result<(
        MultilinearPolynomial<F>,
        MultilinearPolynomial<F>,
        MultilinearPolynomial<F>,
    ), String> {
        let num_gates = self.gates.len();
        let padded_size = num_gates.next_power_of_two();
        
        let mut w_a_vals = Vec::with_capacity(padded_size);
        let mut w_b_vals = Vec::with_capacity(padded_size);
        let mut w_c_vals = Vec::with_capacity(padded_size);
        
        for gate in &self.gates {
            w_a_vals.push(wire_values[gate.wire_a]);
            w_b_vals.push(wire_values[gate.wire_b]);
            w_c_vals.push(wire_values[gate.wire_c]);
        }
        
        // Pad to power of 2
        w_a_vals.resize(padded_size, F::zero());
        w_b_vals.resize(padded_size, F::zero());
        w_c_vals.resize(padded_size, F::zero());
        
        Ok((
            MultilinearPolynomial::from_evaluations(w_a_vals)?,
            MultilinearPolynomial::from_evaluations(w_b_vals)?,
            MultilinearPolynomial::from_evaluations(w_c_vals)?,
        ))
    }
}

/// Plonkish circuit builder
pub struct PlonkishBuilder<F: Field> {
    /// Circuit being built
    circuit: PlonkishCircuit<F>,
    
    /// Next available wire index
    next_wire: usize,
}

impl<F: Field> PlonkishBuilder<F> {
    /// Create new builder
    pub fn new(num_public_inputs: usize) -> Self {
        Self {
            circuit: PlonkishCircuit::new(0, num_public_inputs),
            next_wire: num_public_inputs,
        }
    }
    
    /// Allocate new wire
    pub fn alloc_wire(&mut self) -> usize {
        let wire = self.next_wire;
        self.next_wire += 1;
        self.circuit.num_wires = self.next_wire;
        wire
    }
    
    /// Add addition gate and return output wire
    pub fn add(&mut self, a: usize, b: usize) -> usize {
        let c = self.alloc_wire();
        self.circuit.add_gate(PlonkishGate::addition(a, b, c));
        c
    }
    
    /// Add multiplication gate and return output wire
    pub fn mul(&mut self, a: usize, b: usize) -> usize {
        let c = self.alloc_wire();
        self.circuit.add_gate(PlonkishGate::multiplication(a, b, c));
        c
    }
    
    /// Add constant gate and return output wire
    pub fn constant(&mut self, value: F) -> usize {
        let c = self.alloc_wire();
        self.circuit.add_gate(PlonkishGate::constant(value, c));
        c
    }
    
    /// Enforce equality between two wires
    pub fn enforce_equal(&mut self, a: usize, b: usize) {
        self.circuit.add_copy_constraint(a, b);
    }
    
    /// Add range check for wire
    pub fn range_check(&mut self, wire: usize, bits: usize) {
        let table_name = format!("range_{}", bits);
        
        // Add table if not exists
        if !self.circuit.lookup_tables.contains_key(&table_name) {
            self.circuit.add_lookup_table(LookupTable::range_table(bits));
        }
        
        self.circuit.add_lookup_constraint(wire, table_name);
    }
    
    /// Build final circuit
    pub fn build(self) -> PlonkishCircuit<F> {
        self.circuit
    }
}
