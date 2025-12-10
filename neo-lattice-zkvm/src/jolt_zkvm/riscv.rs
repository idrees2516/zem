// RISC-V instruction definitions and decoding

/// RISC-V instruction types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiscVInstruction {
    // R-type: register-register operations
    Add, Sub, And, Or, Xor, Sll, Srl, Sra,
    Slt, Sltu, Mul, Mulh, Div, Rem,
    
    // I-type: immediate operations
    Addi, Andi, Ori, Xori, Slti, Sltiu,
    Slli, Srli, Srai,
    
    // Load/Store
    Lb, Lh, Lw, Ld, Lbu, Lhu, Lwu,
    Sb, Sh, Sw, Sd,
    
    // Branch
    Beq, Bne, Blt, Bge, Bltu, Bgeu,
    
    // Jump
    Jal, Jalr,
    
    // Upper immediate
    Lui, Auipc,
    
    // System
    Ecall, Ebreak,
}

impl RiscVInstruction {
    /// Check if instruction is a memory operation
    pub fn is_memory_op(&self) -> bool {
        matches!(self,
            RiscVInstruction::Lb | RiscVInstruction::Lh | RiscVInstruction::Lw | 
            RiscVInstruction::Ld | RiscVInstruction::Lbu | RiscVInstruction::Lhu | 
            RiscVInstruction::Lwu | RiscVInstruction::Sb | RiscVInstruction::Sh | 
            RiscVInstruction::Sw | RiscVInstruction::Sd
        )
    }
    
    /// Check if instruction is a load
    pub fn is_load(&self) -> bool {
        matches!(self,
            RiscVInstruction::Lb | RiscVInstruction::Lh | RiscVInstruction::Lw | 
            RiscVInstruction::Ld | RiscVInstruction::Lbu | RiscVInstruction::Lhu | 
            RiscVInstruction::Lwu
        )
    }
    
    /// Check if instruction is a store
    pub fn is_store(&self) -> bool {
        matches!(self,
            RiscVInstruction::Sb | RiscVInstruction::Sh | 
            RiscVInstruction::Sw | RiscVInstruction::Sd
        )
    }
    
    /// Get number of source registers
    pub fn num_source_registers(&self) -> usize {
        match self {
            // R-type uses 2 source registers
            RiscVInstruction::Add | RiscVInstruction::Sub | RiscVInstruction::And |
            RiscVInstruction::Or | RiscVInstruction::Xor | RiscVInstruction::Sll |
            RiscVInstruction::Srl | RiscVInstruction::Sra | RiscVInstruction::Slt |
            RiscVInstruction::Sltu | RiscVInstruction::Mul | RiscVInstruction::Mulh |
            RiscVInstruction::Div | RiscVInstruction::Rem => 2,
            
            // Stores use 2 (address base + value)
            RiscVInstruction::Sb | RiscVInstruction::Sh | 
            RiscVInstruction::Sw | RiscVInstruction::Sd => 2,
            
            // Branches use 2
            RiscVInstruction::Beq | RiscVInstruction::Bne | RiscVInstruction::Blt |
            RiscVInstruction::Bge | RiscVInstruction::Bltu | RiscVInstruction::Bgeu => 2,
            
            // I-type and loads use 1
            RiscVInstruction::Addi | RiscVInstruction::Andi | RiscVInstruction::Ori |
            RiscVInstruction::Xori | RiscVInstruction::Slti | RiscVInstruction::Sltiu |
            RiscVInstruction::Slli | RiscVInstruction::Srli | RiscVInstruction::Srai |
            RiscVInstruction::Lb | RiscVInstruction::Lh | RiscVInstruction::Lw |
            RiscVInstruction::Ld | RiscVInstruction::Lbu | RiscVInstruction::Lhu |
            RiscVInstruction::Lwu | RiscVInstruction::Jalr => 1,
            
            // Upper immediate and Jal use 0
            RiscVInstruction::Lui | RiscVInstruction::Auipc | RiscVInstruction::Jal => 0,
            
            // System instructions use 0
            RiscVInstruction::Ecall | RiscVInstruction::Ebreak => 0,
        }
    }
}

/// Decoded RISC-V instruction with all fields
#[derive(Clone, Debug)]
pub struct DecodedInstruction {
    /// Instruction opcode
    pub opcode: RiscVInstruction,
    
    /// Destination register (0-31)
    pub rd: usize,
    
    /// First source register (0-31)
    pub rs1: usize,
    
    /// Second source register (0-31)
    pub rs2: usize,
    
    /// Immediate value (sign-extended)
    pub imm: i64,
    
    /// Program counter address
    pub address: u64,
}

impl DecodedInstruction {
    /// Decode a 32-bit RISC-V instruction
    pub fn decode(inst: u32, address: u64) -> Result<Self, String> {
        let opcode = inst & 0x7F;
        let rd = ((inst >> 7) & 0x1F) as usize;
        let funct3 = (inst >> 12) & 0x7;
        let rs1 = ((inst >> 15) & 0x1F) as usize;
        let rs2 = ((inst >> 20) & 0x1F) as usize;
        let funct7 = inst >> 25;
        
        // Decode opcode
        let decoded_op = match opcode {
            0x33 => { // R-type
                match (funct3, funct7) {
                    (0x0, 0x00) => RiscVInstruction::Add,
                    (0x0, 0x20) => RiscVInstruction::Sub,
                    (0x7, 0x00) => RiscVInstruction::And,
                    (0x6, 0x00) => RiscVInstruction::Or,
                    (0x4, 0x00) => RiscVInstruction::Xor,
                    (0x1, 0x00) => RiscVInstruction::Sll,
                    (0x5, 0x00) => RiscVInstruction::Srl,
                    (0x5, 0x20) => RiscVInstruction::Sra,
                    (0x2, 0x00) => RiscVInstruction::Slt,
                    (0x3, 0x00) => RiscVInstruction::Sltu,
                    (0x0, 0x01) => RiscVInstruction::Mul,
                    (0x1, 0x01) => RiscVInstruction::Mulh,
                    (0x4, 0x01) => RiscVInstruction::Div,
                    (0x6, 0x01) => RiscVInstruction::Rem,
                    _ => return Err(format!("Unknown R-type: funct3={:x}, funct7={:x}", funct3, funct7)),
                }
            }
            0x13 => { // I-type
                match funct3 {
                    0x0 => RiscVInstruction::Addi,
                    0x7 => RiscVInstruction::Andi,
                    0x6 => RiscVInstruction::Ori,
                    0x4 => RiscVInstruction::Xori,
                    0x2 => RiscVInstruction::Slti,
                    0x3 => RiscVInstruction::Sltiu,
                    0x1 => RiscVInstruction::Slli,
                    0x5 => {
                        if funct7 == 0x00 {
                            RiscVInstruction::Srli
                        } else {
                            RiscVInstruction::Srai
                        }
                    }
                    _ => return Err(format!("Unknown I-type: funct3={:x}", funct3)),
                }
            }
            0x03 => { // Load
                match funct3 {
                    0x0 => RiscVInstruction::Lb,
                    0x1 => RiscVInstruction::Lh,
                    0x2 => RiscVInstruction::Lw,
                    0x3 => RiscVInstruction::Ld,
                    0x4 => RiscVInstruction::Lbu,
                    0x5 => RiscVInstruction::Lhu,
                    0x6 => RiscVInstruction::Lwu,
                    _ => return Err(format!("Unknown load: funct3={:x}", funct3)),
                }
            }
            0x23 => { // Store
                match funct3 {
                    0x0 => RiscVInstruction::Sb,
                    0x1 => RiscVInstruction::Sh,
                    0x2 => RiscVInstruction::Sw,
                    0x3 => RiscVInstruction::Sd,
                    _ => return Err(format!("Unknown store: funct3={:x}", funct3)),
                }
            }
            0x63 => { // Branch
                match funct3 {
                    0x0 => RiscVInstruction::Beq,
                    0x1 => RiscVInstruction::Bne,
                    0x4 => RiscVInstruction::Blt,
                    0x5 => RiscVInstruction::Bge,
                    0x6 => RiscVInstruction::Bltu,
                    0x7 => RiscVInstruction::Bgeu,
                    _ => return Err(format!("Unknown branch: funct3={:x}", funct3)),
                }
            }
            0x6F => RiscVInstruction::Jal,
            0x67 => RiscVInstruction::Jalr,
            0x37 => RiscVInstruction::Lui,
            0x17 => RiscVInstruction::Auipc,
            0x73 => {
                if inst == 0x00000073 {
                    RiscVInstruction::Ecall
                } else if inst == 0x00100073 {
                    RiscVInstruction::Ebreak
                } else {
                    return Err(format!("Unknown system instruction: {:08x}", inst));
                }
            }
            _ => return Err(format!("Unknown opcode: {:02x}", opcode)),
        };
        
        // Extract immediate based on instruction type
        let imm = Self::extract_immediate(inst, &decoded_op);
        
        Ok(DecodedInstruction {
            opcode: decoded_op,
            rd,
            rs1,
            rs2,
            imm,
            address,
        })
    }
    
    /// Extract immediate value based on instruction format
    fn extract_immediate(inst: u32, opcode: &RiscVInstruction) -> i64 {
        match opcode {
            // I-type immediate (12 bits, sign-extended)
            RiscVInstruction::Addi | RiscVInstruction::Andi | RiscVInstruction::Ori |
            RiscVInstruction::Xori | RiscVInstruction::Slti | RiscVInstruction::Sltiu |
            RiscVInstruction::Lb | RiscVInstruction::Lh | RiscVInstruction::Lw |
            RiscVInstruction::Ld | RiscVInstruction::Lbu | RiscVInstruction::Lhu |
            RiscVInstruction::Lwu | RiscVInstruction::Jalr => {
                ((inst as i32) >> 20) as i64
            }
            
            // Shift immediate (5 or 6 bits, unsigned)
            RiscVInstruction::Slli | RiscVInstruction::Srli | RiscVInstruction::Srai => {
                ((inst >> 20) & 0x3F) as i64
            }
            
            // S-type immediate (12 bits, sign-extended)
            RiscVInstruction::Sb | RiscVInstruction::Sh | RiscVInstruction::Sw | RiscVInstruction::Sd => {
                let imm_11_5 = ((inst >> 25) & 0x7F) as i32;
                let imm_4_0 = ((inst >> 7) & 0x1F) as i32;
                (((imm_11_5 << 5) | imm_4_0) << 20 >> 20) as i64
            }
            
            // B-type immediate (13 bits, sign-extended, shifted left by 1)
            RiscVInstruction::Beq | RiscVInstruction::Bne | RiscVInstruction::Blt |
            RiscVInstruction::Bge | RiscVInstruction::Bltu | RiscVInstruction::Bgeu => {
                let imm_12 = ((inst >> 31) & 0x1) as i32;
                let imm_10_5 = ((inst >> 25) & 0x3F) as i32;
                let imm_4_1 = ((inst >> 8) & 0xF) as i32;
                let imm_11 = ((inst >> 7) & 0x1) as i32;
                (((imm_12 << 12) | (imm_11 << 11) | (imm_10_5 << 5) | (imm_4_1 << 1)) << 19 >> 19) as i64
            }
            
            // U-type immediate (20 bits, shifted left by 12)
            RiscVInstruction::Lui | RiscVInstruction::Auipc => {
                ((inst & 0xFFFFF000) as i32) as i64
            }
            
            // J-type immediate (21 bits, sign-extended, shifted left by 1)
            RiscVInstruction::Jal => {
                let imm_20 = ((inst >> 31) & 0x1) as i32;
                let imm_10_1 = ((inst >> 21) & 0x3FF) as i32;
                let imm_11 = ((inst >> 20) & 0x1) as i32;
                let imm_19_12 = ((inst >> 12) & 0xFF) as i32;
                (((imm_20 << 20) | (imm_19_12 << 12) | (imm_11 << 11) | (imm_10_1 << 1)) << 11 >> 11) as i64
            }
            
            _ => 0,
        }
    }
    
    /// Decompose instruction for lookup table evaluation
    /// Splits 64-bit operations into multiple 16-bit lookups (Lasso-style)
    pub fn decompose(&self) -> InstructionDecomposition {
        InstructionDecomposition {
            opcode: self.opcode,
            chunks: vec![
                (self.rs1 as u16, self.rs2 as u16),
                ((self.imm & 0xFFFF) as u16, ((self.imm >> 16) & 0xFFFF) as u16),
                ((self.imm >> 32) as u16, (self.rd as u16)),
            ],
        }
    }
}

/// Instruction decomposition for lookup tables
#[derive(Clone, Debug)]
pub struct InstructionDecomposition {
    pub opcode: RiscVInstruction,
    pub chunks: Vec<(u16, u16)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_decode_add() {
        // add x1, x2, x3: 0x003100B3
        let inst = 0x003100B3u32;
        let decoded = DecodedInstruction::decode(inst, 0).unwrap();
        assert_eq!(decoded.opcode, RiscVInstruction::Add);
        assert_eq!(decoded.rd, 1);
        assert_eq!(decoded.rs1, 2);
        assert_eq!(decoded.rs2, 3);
    }
    
    #[test]
    fn test_decode_addi() {
        // addi x1, x2, 42: 0x02A10093
        let inst = 0x02A10093u32;
        let decoded = DecodedInstruction::decode(inst, 0).unwrap();
        assert_eq!(decoded.opcode, RiscVInstruction::Addi);
        assert_eq!(decoded.rd, 1);
        assert_eq!(decoded.rs1, 2);
        assert_eq!(decoded.imm, 42);
    }
    
    #[test]
    fn test_decode_lw() {
        // lw x1, 0(x2): 0x00012083
        let inst = 0x00012083u32;
        let decoded = DecodedInstruction::decode(inst, 0).unwrap();
        assert_eq!(decoded.opcode, RiscVInstruction::Lw);
        assert_eq!(decoded.rd, 1);
        assert_eq!(decoded.rs1, 2);
        assert_eq!(decoded.imm, 0);
    }
    
    #[test]
    fn test_is_memory_op() {
        assert!(RiscVInstruction::Lw.is_memory_op());
        assert!(RiscVInstruction::Sw.is_memory_op());
        assert!(!RiscVInstruction::Add.is_memory_op());
    }
    
    #[test]
    fn test_num_source_registers() {
        assert_eq!(RiscVInstruction::Add.num_source_registers(), 2);
        assert_eq!(RiscVInstruction::Addi.num_source_registers(), 1);
        assert_eq!(RiscVInstruction::Lui.num_source_registers(), 0);
    }
}
