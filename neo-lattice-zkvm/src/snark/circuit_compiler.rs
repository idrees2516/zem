// Circuit Compiler Integration - Task 11.3
// Supports Plonkish, R1CS, and CCS constraint systems

use crate::field::Field;
use crate::snark::speedy_spartan::{SpeedySpartan, PlonkishGate, GateType};
use crate::snark::spartan_plusplus::{SpartanPlusPlus, CCS, SparseMatrix};
use std::collections::HashMap;

/// R1CS (Rank-1 Constraint System) representation
/// 
/// Constraints: (A·z) ◦ (B·z) = C·z
/// where ◦ is Hadamard (element-wise) product
#[derive(Clone, Debug)]
pub struct R1CS<F: Field> {
    /// Number of constraints
    pub num_constraints: usize,
    
    /// Number of variables
    pub num_variables: usize,
    
    /// A matrix
    pub a_matrix: SparseMatrix<F>,
    
    /// B matrix
    pub b_matrix: SparseMatrix<F>,
    
    /// C matrix
    pub c_matrix: SparseMatrix<F>,
}

/// Plonkish circuit description
#[derive(Clone, Debug)]
pub struct PlonkishCircuit<F: Field> {
    /// Gates
    pub gates: Vec<PlonkishGate<F>>,
    
    /// Wiring (maps gate outputs to inputs)
    pub wiring: HashMap<usize, Vec<usize>>,
    
    /// Public inputs
    pub public_inputs: Vec<usize>,
}

/// Circuit compiler
/// 
/// Supports:
/// - Plonkish → SpeedySpartan
/// - R1CS → CCS → Spartan++
/// - CCS → Spartan++
pub struct CircuitCompiler;

impl CircuitCompiler {
    /// Parse Plonkish circuit description
    /// 
    /// Format:
    /// gate <type> <left_input> <right_input> <output> [selector]
    /// 
    /// Example:
    /// gate add 0 1 2
    /// gate mul 2 3 4
    pub fn parse_plonkish<F: Field>(description: &str) -> Result<PlonkishCircuit<F>, String> {
        let mut gates = Vec::new();
        let mut wiring = HashMap::new();
        
        for line in description.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                return Err(format!("Invalid gate specification: {}", line));
            }
            
            if parts[0] != "gate" {
                return Err(format!("Expected 'gate', got '{}'", parts[0]));
            }
            
            let gate_type = match parts[1] {
                "add" => GateType::Add,
                "mul" => GateType::Mul,
                "const" => {
                    let val = parts.get(5)
                        .and_then(|s| s.parse::<u64>().ok())
                        .ok_or_else(|| format!("Missing constant value"))?;
                    GateType::Constant(val)
                }
                _ => GateType::Custom,
            };
            
            let left_input = parts[2].parse::<usize>()
                .map_err(|_| format!("Invalid left input: {}", parts[2]))?;
            let right_input = parts[3].parse::<usize>()
                .map_err(|_| format!("Invalid right input: {}", parts[3]))?;
            let output = parts[4].parse::<usize>()
                .map_err(|_| format!("Invalid output: {}", parts[4]))?;
            
            let selector = if parts.len() > 5 {
                F::from_u64(parts[5].parse::<u64>().unwrap_or(1))
            } else {
                F::one()
            };
            
            gates.push(PlonkishGate {
                gate_type,
                left_input,
                right_input,
                output,
                selector,
            });
            
            // Track wiring
            wiring.entry(output).or_insert_with(Vec::new).push(gates.len() - 1);
        }
        
        Ok(PlonkishCircuit {
            gates,
            wiring,
            public_inputs: Vec::new(),
        })
    }
    
    /// Generate SpeedySpartan proof from Plonkish circuit
    pub fn prove_plonkish<F: Field>(
        circuit: PlonkishCircuit<F>,
        witness: &[F],
    ) -> Result<crate::snark::speedy_spartan::SpeedySpartanProof<F>, String> {
        let mut prover = SpeedySpartan::new(circuit.gates, witness)?;
        prover.prove()
    }
    
    /// Parse R1CS constraint system
    /// 
    /// Format:
    /// constraint <a_entries> | <b_entries> | <c_entries>
    /// 
    /// where entries are: row,col,value;...
    pub fn parse_r1cs<F: Field>(description: &str) -> Result<R1CS<F>, String> {
        let mut a_entries = Vec::new();
        let mut b_entries = Vec::new();
        let mut c_entries = Vec::new();
        
        let mut max_row = 0;
        let mut max_col = 0;
        
        for line in description.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() != 3 {
                return Err(format!("Invalid R1CS constraint: {}", line));
            }
            
            // Parse A entries
            for entry_str in parts[0].split(';') {
                if entry_str.is_empty() {
                    continue;
                }
                let (row, col, val) = Self::parse_entry::<F>(entry_str)?;
                a_entries.push((row, col, val));
                max_row = max_row.max(row);
                max_col = max_col.max(col);
            }
            
            // Parse B entries
            for entry_str in parts[1].split(';') {
                if entry_str.is_empty() {
                    continue;
                }
                let (row, col, val) = Self::parse_entry::<F>(entry_str)?;
                b_entries.push((row, col, val));
                max_row = max_row.max(row);
                max_col = max_col.max(col);
            }
            
            // Parse C entries
            for entry_str in parts[2].split(';') {
                if entry_str.is_empty() {
                    continue;
                }
                let (row, col, val) = Self::parse_entry::<F>(entry_str)?;
                c_entries.push((row, col, val));
                max_row = max_row.max(row);
                max_col = max_col.max(col);
            }
        }
        
        Ok(R1CS {
            num_constraints: max_row + 1,
            num_variables: max_col + 1,
            a_matrix: SparseMatrix::new(max_row + 1, max_col + 1, a_entries),
            b_matrix: SparseMatrix::new(max_row + 1, max_col + 1, b_entries),
            c_matrix: SparseMatrix::new(max_row + 1, max_col + 1, c_entries),
        })
    }
    
    /// Parse matrix entry: row,col,value
    fn parse_entry<F: Field>(entry_str: &str) -> Result<(usize, usize, F), String> {
        let parts: Vec<&str> = entry_str.split(',').collect();
        if parts.len() != 3 {
            return Err(format!("Invalid entry: {}", entry_str));
        }
        
        let row = parts[0].parse::<usize>()
            .map_err(|_| format!("Invalid row: {}", parts[0]))?;
        let col = parts[1].parse::<usize>()
            .map_err(|_| format!("Invalid col: {}", parts[1]))?;
        let val = F::from_u64(parts[2].parse::<u64>()
            .map_err(|_| format!("Invalid value: {}", parts[2]))?);
        
        Ok((row, col, val))
    }
    
    /// Convert R1CS to CCS
    /// 
    /// R1CS: (A·z) ◦ (B·z) = C·z
    /// 
    /// CCS equivalent:
    /// (A·z) ◦ (B·z) - C·z = 0
    /// 
    /// Which is: c_0 · (M_0·z ◦ M_1·z) + c_1 · M_2·z = 0
    /// where c_0 = 1, c_1 = -1, M_0 = A, M_1 = B, M_2 = C
    pub fn r1cs_to_ccs<F: Field>(r1cs: R1CS<F>) -> CCS<F> {
        let matrices = vec![
            r1cs.a_matrix,
            r1cs.b_matrix,
            r1cs.c_matrix,
        ];
        
        let constants = vec![
            F::one(),      // Coefficient for A·z ◦ B·z
            -F::one(),     // Coefficient for C·z
        ];
        
        let index_sets = vec![
            vec![0, 1],    // A·z ◦ B·z (Hadamard product of M_0 and M_1)
            vec![2],       // C·z (just M_2)
        ];
        
        CCS {
            m: r1cs.num_constraints,
            n: r1cs.num_variables,
            t: 3,
            matrices,
            constants,
            index_sets,
        }
    }
    
    /// Generate Spartan++ proof from R1CS
    pub fn prove_r1cs<F: Field>(
        r1cs: R1CS<F>,
        witness: Vec<F>,
    ) -> Result<crate::snark::spartan_plusplus::SpartanPlusPlusProof<F>, String> {
        // Convert R1CS to CCS
        let ccs = Self::r1cs_to_ccs(r1cs);
        
        // Generate Spartan++ proof
        let mut prover = SpartanPlusPlus::new(ccs, witness)?;
        prover.prove()
    }
    
    /// Parse CCS constraint system
    /// 
    /// Format:
    /// ccs <num_constraints> <num_variables> <num_matrices>
    /// matrix <id> <entries>
    /// constraint <constant> <index_set>
    pub fn parse_ccs<F: Field>(description: &str) -> Result<CCS<F>, String> {
        let mut lines = description.lines();
        
        // Parse header
        let header = lines.next().ok_or("Missing CCS header")?;
        let parts: Vec<&str> = header.split_whitespace().collect();
        if parts.len() != 4 || parts[0] != "ccs" {
            return Err(format!("Invalid CCS header: {}", header));
        }
        
        let m = parts[1].parse::<usize>()
            .map_err(|_| format!("Invalid num_constraints"))?;
        let n = parts[2].parse::<usize>()
            .map_err(|_| format!("Invalid num_variables"))?;
        let t = parts[3].parse::<usize>()
            .map_err(|_| format!("Invalid num_matrices"))?;
        
        let mut matrices = vec![SparseMatrix::new(m, n, Vec::new()); t];
        let mut constants = Vec::new();
        let mut index_sets = Vec::new();
        
        // Parse matrices and constraints
        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            let parts: Vec<&str> = line.split_whitespace().collect();
            
            if parts[0] == "matrix" {
                let id = parts[1].parse::<usize>()
                    .map_err(|_| format!("Invalid matrix id"))?;
                
                // Parse matrix entries
                let mut entries = Vec::new();
                for entry_str in parts[2..].iter() {
                    let (row, col, val) = Self::parse_entry::<F>(entry_str)?;
                    entries.push((row, col, val));
                }
                
                matrices[id] = SparseMatrix::new(m, n, entries);
            } else if parts[0] == "constraint" {
                let constant = F::from_u64(parts[1].parse::<u64>()
                    .map_err(|_| format!("Invalid constant"))?);
                constants.push(constant);
                
                let index_set: Vec<usize> = parts[2..]
                    .iter()
                    .filter_map(|s| s.parse::<usize>().ok())
                    .collect();
                index_sets.push(index_set);
            }
        }
        
        Ok(CCS {
            m,
            n,
            t,
            matrices,
            constants,
            index_sets,
        })
    }
    
    /// Generate Spartan++ proof from CCS
    pub fn prove_ccs<F: Field>(
        ccs: CCS<F>,
        witness: Vec<F>,
    ) -> Result<crate::snark::spartan_plusplus::SpartanPlusPlusProof<F>, String> {
        let mut prover = SpartanPlusPlus::new(ccs, witness)?;
        prover.prove()
    }
    
    /// Optimize constraint system conversion
    /// 
    /// Common patterns:
    /// - Boolean constraints: x(1-x) = 0
    /// - Range constraints: x ∈ [0, 2^k)
    /// - Lookup constraints: y = table[x]
    pub fn optimize_conversion<F: Field>(ccs: &mut CCS<F>) {
        // Identify and optimize common patterns
        
        // Pattern 1: Boolean constraints
        // x(1-x) = 0 can be represented more efficiently
        
        // Pattern 2: Range constraints
        // Can use bit decomposition optimization
        
        // Pattern 3: Lookup constraints
        // Can use Shout protocol directly
        
        // For now, this is a placeholder for future optimizations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::m61::M61;
    
    #[test]
    fn test_parse_plonkish() {
        let description = r#"
            gate add 0 1 2
            gate mul 2 3 4
        "#;
        
        let circuit = CircuitCompiler::parse_plonkish::<M61>(description).unwrap();
        
        assert_eq!(circuit.gates.len(), 2);
        assert_eq!(circuit.gates[0].gate_type, GateType::Add);
        assert_eq!(circuit.gates[1].gate_type, GateType::Mul);
        
        println!("✓ Plonkish parsing works");
    }
    
    #[test]
    fn test_r1cs_to_ccs() {
        let a_entries = vec![(0, 0, M61::from_u64(1))];
        let b_entries = vec![(0, 1, M61::from_u64(1))];
        let c_entries = vec![(0, 2, M61::from_u64(1))];
        
        let r1cs = R1CS {
            num_constraints: 1,
            num_variables: 3,
            a_matrix: SparseMatrix::new(1, 3, a_entries),
            b_matrix: SparseMatrix::new(1, 3, b_entries),
            c_matrix: SparseMatrix::new(1, 3, c_entries),
        };
        
        let ccs = CircuitCompiler::r1cs_to_ccs(r1cs);
        
        assert_eq!(ccs.m, 1);
        assert_eq!(ccs.n, 3);
        assert_eq!(ccs.t, 3);
        assert_eq!(ccs.matrices.len(), 3);
        
        println!("✓ R1CS to CCS conversion works");
    }
    
    #[test]
    fn test_parse_ccs() {
        let description = r#"
            ccs 1 3 2
            matrix 0 0,0,1
            matrix 1 0,1,1
            constraint 1 0 1
        "#;
        
        let ccs = CircuitCompiler::parse_ccs::<M61>(description).unwrap();
        
        assert_eq!(ccs.m, 1);
        assert_eq!(ccs.n, 3);
        assert_eq!(ccs.t, 2);
        
        println!("✓ CCS parsing works");
    }
}
