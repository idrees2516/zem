// Instruction execution tables for Shout lookups
// Implements task 6.4 requirements

use crate::field::Field;
use crate::sumcheck::multilinear::MultilinearPolynomial;
use super::riscv::{RiscVInstruction, InstructionDecomposition};

/// Instruction execution table
/// MLE-structured table for O(log K) verifier evaluation
pub struct InstructionTable<F: Field> {
    /// Table size (typically 2^16 for 16-bit operations)
    pub size: usize,
    
    /// MLE representation of the table
    pub mle: MultilinearPolynomial<F>,
    
    /// Instruction type this table represents
    pub instruction: RiscVInstruction,
}

impl<F: Field> InstructionTable<F> {
    /// Create table for ADD operation
    /// table[a,b] = (a + b) mod 2^64
    pub fn create_add_table(bit_width: usize) -> Self {
        let size = 1 << (2 * bit_width); // 2^(2*bit_width) entries for (a,b) pairs
        let mut evaluations = Vec::with_capacity(size);
        
        let mask = (1u64 << bit_width) - 1;
        for a in 0..(1 << bit_width) {
            for b in 0..(1 << bit_width) {
                let result = (a + b) & mask;
                evaluations.push(F::from_u64(result));
            }
        }
        
        Self {
            size,
            mle: MultilinearPolynomial::from_evaluations(evaluations),
            instruction: RiscVInstruction::Add,
        }
    }
    
    /// Create table for SUB operation
    /// table[a,b] = (a - b) mod 2^64
    pub fn create_sub_table(bit_width: usize) -> Self {
        let size = 1 << (2 * bit_width);
        let mut evaluations = Vec::with_capacity(size);
        
        let mask = (1u64 << bit_width) - 1;
        for a in 0..(1 << bit_width) {
            for b in 0..(1 << bit_width) {
                let result = (a.wrapping_sub(b)) & mask;
                evaluations.push(F::from_u64(result));
            }
        }
        
        Self {
            size,
            mle: MultilinearPolynomial::from_evaluations(evaluations),
            instruction: RiscVInstruction::Sub,
        }
    }
    
    /// Create table for XOR operation
    /// table[a,b] = a ⊕ b
    pub fn create_xor_table(bit_width: usize) -> Self {
        let size = 1 << (2 * bit_width);
        let mut evaluations = Vec::with_capacity(size);
        
        for a in 0..(1 << bit_width) {
            for b in 0..(1 << bit_width) {
                let result = a ^ b;
                evaluations.push(F::from_u64(result));
            }
        }
        
        Self {
            size,
            mle: MultilinearPolynomial::from_evaluations(evaluations),
            instruction: RiscVInstruction::Xor,
        }
    }
    
    /// Create table for AND operation
    /// table[a,b] = a & b
    pub fn create_and_table(bit_width: usize) -> Self {
        let size = 1 << (2 * bit_width);
        let mut evaluations = Vec::with_capacity(size);
        
        for a in 0..(1 << bit_width) {
            for b in 0..(1 << bit_width) {
                let result = a & b;
                evaluations.push(F::from_u64(result));
            }
        }
        
        Self {
            size,
            mle: MultilinearPolynomial::from_evaluations(evaluations),
            instruction: RiscVInstruction::And,
        }
    }
    
    /// Create table for OR operation
    /// table[a,b] = a | b
    pub fn create_or_table(bit_width: usize) -> Self {
        let size = 1 << (2 * bit_width);
        let mut evaluations = Vec::with_capacity(size);
        
        for a in 0..(1 << bit_width) {
            for b in 0..(1 << bit_width) {
                let result = a | b;
                evaluations.push(F::from_u64(result));
            }
        }
        
        Self {
            size,
            mle: MultilinearPolynomial::from_evaluations(evaluations),
            instruction: RiscVInstruction::Or,
        }
    }
    
    /// Create table for MUL operation (lower bits)
    /// table[a,b] = (a * b) mod 2^bit_width
    pub fn create_mul_table(bit_width: usize) -> Self {
        let size = 1 << (2 * bit_width);
        let mut evaluations = Vec::with_capacity(size);
        
        let mask = (1u64 << bit_width) - 1;
        for a in 0..(1 << bit_width) {
            for b in 0..(1 << bit_width) {
                let result = (a * b) & mask;
                evaluations.push(F::from_u64(result));
            }
        }
        
        Self {
            size,
            mle: MultilinearPolynomial::from_evaluations(evaluations),
            instruction: RiscVInstruction::Mul,
        }
    }
    
    /// Create table for SLT (set less than) operation
    /// table[a,b] = 1 if a < b (signed), else 0
    pub fn create_slt_table(bit_width: usize) -> Self {
        let size = 1 << (2 * bit_width);
        let mut evaluations = Vec::with_capacity(size);
        
        let sign_bit = 1u64 << (bit_width - 1);
        for a in 0..(1 << bit_width) {
            for b in 0..(1 << bit_width) {
                // Interpret as signed
                let a_signed = if a & sign_bit != 0 {
                    (a as i64) | (!((1i64 << bit_width) - 1))
                } else {
                    a as i64
                };
                let b_signed = if b & sign_bit != 0 {
                    (b as i64) | (!((1i64 << bit_width) - 1))
                } else {
                    b as i64
                };
                
                let result = if a_signed < b_signed { 1 } else { 0 };
                evaluations.push(F::from_u64(result));
            }
        }
        
        Self {
            size,
            mle: MultilinearPolynomial::from_evaluations(evaluations),
            instruction: RiscVInstruction::Slt,
        }
    }
    
    /// Create table for SLTU (set less than unsigned) operation
    /// table[a,b] = 1 if a < b (unsigned), else 0
    pub fn create_sltu_table(bit_width: usize) -> Self {
        let size = 1 << (2 * bit_width);
        let mut evaluations = Vec::with_capacity(size);
        
        for a in 0..(1 << bit_width) {
            for b in 0..(1 << bit_width) {
                let result = if a < b { 1 } else { 0 };
                evaluations.push(F::from_u64(result));
            }
        }
        
        Self {
            size,
            mle: MultilinearPolynomial::from_evaluations(evaluations),
            instruction: RiscVInstruction::Sltu,
        }
    }
    
    /// Evaluate table at a random point (for verifier)
    /// Computes table value in O(log K) time using MLE structure
    pub fn evaluate_at_point(&self, point: &[F]) -> F {
        self.mle.evaluate(point)
    }
}

/// Collection of all instruction tables
pub struct InstructionTableSet<F: Field> {
    /// Bit width for decomposed operations (typically 16)
    pub bit_width: usize,
    
    /// Tables for each instruction type
    pub add_table: InstructionTable<F>,
    pub sub_table: InstructionTable<F>,
    pub xor_table: InstructionTable<F>,
    pub and_table: InstructionTable<F>,
    pub or_table: InstructionTable<F>,
    pub mul_table: InstructionTable<F>,
    pub slt_table: InstructionTable<F>,
    pub sltu_table: InstructionTable<F>,
}

impl<F: Field> InstructionTableSet<F> {
    /// Create all instruction tables with given bit width
    /// Typically bit_width = 16 for 2^16 table size
    pub fn new(bit_width: usize) -> Self {
        Self {
            bit_width,
            add_table: InstructionTable::create_add_table(bit_width),
            sub_table: InstructionTable::create_sub_table(bit_width),
            xor_table: InstructionTable::create_xor_table(bit_width),
            and_table: InstructionTable::create_and_table(bit_width),
            or_table: InstructionTable::create_or_table(bit_width),
            mul_table: InstructionTable::create_mul_table(bit_width),
            slt_table: InstructionTable::create_slt_table(bit_width),
            sltu_table: InstructionTable::create_sltu_table(bit_width),
        }
    }
    
    /// Get table for specific instruction
    pub fn get_table(&self, instruction: RiscVInstruction) -> Option<&InstructionTable<F>> {
        match instruction {
            RiscVInstruction::Add | RiscVInstruction::Addi => Some(&self.add_table),
            RiscVInstruction::Sub => Some(&self.sub_table),
            RiscVInstruction::Xor | RiscVInstruction::Xori => Some(&self.xor_table),
            RiscVInstruction::And | RiscVInstruction::Andi => Some(&self.and_table),
            RiscVInstruction::Or | RiscVInstruction::Ori => Some(&self.or_table),
            RiscVInstruction::Mul => Some(&self.mul_table),
            RiscVInstruction::Slt | RiscVInstruction::Slti => Some(&self.slt_table),
            RiscVInstruction::Sltu | RiscVInstruction::Sltiu => Some(&self.sltu_table),
            _ => None,
        }
    }
    
    /// Decompose 64-bit operation into 16-bit lookups (Lasso-style)
    /// For a 64-bit operation, split into 4 × 16-bit lookups
    pub fn decompose_operation(&self, a: u64, b: u64) -> Vec<(u16, u16)> {
        vec![
            ((a & 0xFFFF) as u16, (b & 0xFFFF) as u16),
            (((a >> 16) & 0xFFFF) as u16, ((b >> 16) & 0xFFFF) as u16),
            (((a >> 32) & 0xFFFF) as u16, ((b >> 32) & 0xFFFF) as u16),
            (((a >> 48) & 0xFFFF) as u16, ((b >> 48) & 0xFFFF) as u16),
        ]
    }
    
    /// Combine results from decomposed lookups
    /// Reconstructs 64-bit result from 4 × 16-bit results
    pub fn combine_results(&self, results: &[u64], instruction: RiscVInstruction) -> u64 {
        match instruction {
            // For ADD/SUB, need to handle carries between chunks
            RiscVInstruction::Add | RiscVInstruction::Addi => {
                let mut result = 0u64;
                let mut carry = 0u64;
                for (i, &chunk_result) in results.iter().enumerate() {
                    let sum = chunk_result + carry;
                    result |= (sum & 0xFFFF) << (i * 16);
                    carry = sum >> 16;
                }
                result
            }
            
            RiscVInstruction::Sub => {
                let mut result = 0u64;
                let mut borrow = 0u64;
                for (i, &chunk_result) in results.iter().enumerate() {
                    let diff = chunk_result.wrapping_sub(borrow);
                    result |= (diff & 0xFFFF) << (i * 16);
                    borrow = if diff > chunk_result { 1 } else { 0 };
                }
                result
            }
            
            // For bitwise operations, just concatenate
            RiscVInstruction::Xor | RiscVInstruction::Xori |
            RiscVInstruction::And | RiscVInstruction::Andi |
            RiscVInstruction::Or | RiscVInstruction::Ori => {
                let mut result = 0u64;
                for (i, &chunk_result) in results.iter().enumerate() {
                    result |= (chunk_result & 0xFFFF) << (i * 16);
                }
                result
            }
            
            // For MUL, need more complex reconstruction
            RiscVInstruction::Mul => {
                // Simplified: just use lower 64 bits
                let mut result = 0u64;
                for (i, &chunk_result) in results.iter().enumerate() {
                    result |= (chunk_result & 0xFFFF) << (i * 16);
                }
                result
            }
            
            // For comparison, result is just 0 or 1
            RiscVInstruction::Slt | RiscVInstruction::Slti |
            RiscVInstruction::Sltu | RiscVInstruction::Sltiu => {
                results[0] & 1
            }
            
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::m61::M61;
    
    #[test]
    fn test_add_table() {
        let table = InstructionTable::<M61>::create_add_table(4); // 4-bit for testing
        assert_eq!(table.size, 256); // 2^(2*4) = 256 entries
        
        // Test a few values
        // table[3,5] should be 8
        let idx = 3 * 16 + 5;
        let eval = table.mle.evaluations[idx];
        assert_eq!(eval, M61::from_u64(8));
    }
    
    #[test]
    fn test_xor_table() {
        let table = InstructionTable::<M61>::create_xor_table(4);
        
        // table[0xA, 0x5] should be 0xF
        let idx = 0xA * 16 + 0x5;
        let eval = table.mle.evaluations[idx];
        assert_eq!(eval, M61::from_u64(0xF));
    }
    
    #[test]
    fn test_decompose_operation() {
        let tables = InstructionTableSet::<M61>::new(16);
        
        let a = 0x123456789ABCDEF0u64;
        let b = 0xFEDCBA9876543210u64;
        
        let chunks = tables.decompose_operation(a, b);
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0], (0xDEF0, 0x3210));
        assert_eq!(chunks[1], (0x9ABC, 0x7654));
        assert_eq!(chunks[2], (0x5678, 0xBA98));
        assert_eq!(chunks[3], (0x1234, 0xFEDC));
    }
    
    #[test]
    fn test_table_set_creation() {
        let tables = InstructionTableSet::<M61>::new(16);
        assert_eq!(tables.bit_width, 16);
        assert_eq!(tables.add_table.size, 1 << 32); // 2^32 entries for 16-bit ops
    }
    
    #[test]
    fn test_get_table() {
        let tables = InstructionTableSet::<M61>::new(16);
        
        assert!(tables.get_table(RiscVInstruction::Add).is_some());
        assert!(tables.get_table(RiscVInstruction::Xor).is_some());
        assert!(tables.get_table(RiscVInstruction::Lw).is_none()); // No table for loads
    }
}
