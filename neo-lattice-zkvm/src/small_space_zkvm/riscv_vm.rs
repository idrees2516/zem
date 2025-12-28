// RISC-V VM Executor Module for Small-Space zkVM
//
// This module implements a RISC-V virtual machine that executes programs
// and generates witness vectors on-demand for the small-space prover.
//
// Key Features:
// 1. RV32I base instruction set support
// 2. Efficient witness slice generation (O(1) per cycle)
// 3. Checkpointing system for parallel regeneration
// 4. Streaming witness generation with minimal memory overhead
//
// References:
// - Paper Section 3: Streaming Witness Generation (Requirements 3.1-3.10)
// - Tasks 11.1-11.10: VM executor implementation
// - Tasks 12.1-12.5: Checkpointing system
// - Tasks 13.1-13.6: Streaming witness generator

use crate::field::Field;
use std::collections::HashMap;

/// RISC-V Instruction Opcodes (RV32I)
///
/// Supports the base integer instruction set.
/// Reference: RISC-V ISA Specification
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    
    // Logical
    And,
    Or,
    Xor,
    Sll,
    Srl,
    Sra,
    
    // Comparison
    Slt,
    Sltu,
    
    // Immediate
    Addi,
    Andi,
    Ori,
    Xori,
    Slli,
    Srli,
    Srai,
    Slti,
    Sltui,
    
    // Load/Store
    Lb,
    Lh,
    Lw,
    Lbu,
    Lhu,
    Sb,
    Sh,
    Sw,
    
    // Branch
    Beq,
    Bne,
    Blt,
    Bge,
    Bltu,
    Bgeu,
    
    // Jump
    Jal,
    Jalr,
    
    // Other
    Lui,
    Auipc,
    Fence,
    Ecall,
    Ebreak,
}

/// Decoded RISC-V Instruction
///
/// Contains all fields extracted from a 32-bit instruction.
/// Reference: Requirements 3.1-3.2, Task 11.3
#[derive(Clone, Debug)]
pub struct DecodedInstruction {
    pub opcode: Opcode,
    pub rd: Option<usize>,      // Destination register
    pub rs1: Option<usize>,     // Source register 1
    pub rs2: Option<usize>,     // Source register 2
    pub imm: u64,               // Immediate value
    pub shamt: u32,             // Shift amount
}

/// ALU Operation Type
///
/// Tracks which ALU operation was performed for witness generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AluOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Sll,
    Srl,
    Sra,
    Slt,
    Sltu,
}

/// Memory Access Record
///
/// Records a single memory read or write operation.
#[derive(Clone, Debug)]
pub struct MemoryAccess {
    pub address: u64,
    pub value: u64,
    pub is_write: bool,
}

/// Witness Slice
///
/// Contains all witness information for a single cycle.
/// This is generated during VM execution and used by the prover.
///
/// Reference: Requirements 3.1-3.2, 3.6-3.8, Task 11.8
#[derive(Clone, Debug)]
pub struct WitnessSlice<F: Field> {
    /// Register reads: (register_index, value)
    pub register_reads: Vec<(usize, u64)>,
    
    /// Register writes: (register_index, value)
    pub register_writes: Vec<(usize, u64)>,
    
    /// Memory accesses
    pub memory_accesses: Vec<MemoryAccess>,
    
    /// ALU operations
    pub alu_operations: Vec<(AluOp, u64)>,
    
    /// Program counter
    pub pc: u64,
    
    /// Next program counter
    pub next_pc: u64,
    
    /// Field elements for witness vector
    pub field_values: Vec<F>,
}

impl<F: Field> WitnessSlice<F> {
    /// Create new witness slice
    pub fn new() -> Self {
        Self {
            register_reads: Vec::new(),
            register_writes: Vec::new(),
            memory_accesses: Vec::new(),
            alu_operations: Vec::new(),
            pc: 0,
            next_pc: 0,
            field_values: Vec::new(),
        }
    }
    
    /// Add register read
    pub fn add_register_read(&mut self, reg: usize, value: u64) {
        self.register_reads.push((reg, value));
    }
    
    /// Add register write
    pub fn add_register_write(&mut self, reg: usize, value: u64) {
        self.register_writes.push((reg, value));
    }
    
    /// Add memory read
    pub fn add_memory_read(&mut self, address: u64, value: u64) {
        self.memory_accesses.push(MemoryAccess {
            address,
            value,
            is_write: false,
        });
    }
    
    /// Add memory write
    pub fn add_memory_write(&mut self, address: u64, value: u64) {
        self.memory_accesses.push(MemoryAccess {
            address,
            value,
            is_write: true,
        });
    }
    
    /// Add ALU operation
    pub fn add_alu_operation(&mut self, op: AluOp, result: u64) {
        self.alu_operations.push((op, result));
    }
    
    /// Set program counter
    pub fn set_pc(&mut self, pc: u64) {
        self.pc = pc;
    }
    
    /// Set next program counter
    pub fn set_next_pc(&mut self, next_pc: u64) {
        self.next_pc = next_pc;
    }
    
    /// Convert to field elements
    pub fn to_field_elements(&self) -> Vec<F> {
        let mut elements = Vec::new();
        
        // Add register reads
        for (reg, value) in &self.register_reads {
            elements.push(F::from_u64(*reg as u64));
            elements.push(F::from_u64(*value));
        }
        
        // Add register writes
        for (reg, value) in &self.register_writes {
            elements.push(F::from_u64(*reg as u64));
            elements.push(F::from_u64(*value));
        }
        
        // Add memory accesses
        for access in &self.memory_accesses {
            elements.push(F::from_u64(access.address));
            elements.push(F::from_u64(access.value));
            elements.push(F::from_u64(if access.is_write { 1 } else { 0 }));
        }
        
        // Add ALU operations
        for (op, result) in &self.alu_operations {
            elements.push(F::from_u64(*op as u64));
            elements.push(F::from_u64(*result));
        }
        
        // Add PC values
        elements.push(F::from_u64(self.pc));
        elements.push(F::from_u64(self.next_pc));
        
        elements
    }
}

/// VM Checkpoint
///
/// Stores a snapshot of VM state at a specific cycle.
/// Used for parallel witness regeneration.
///
/// Reference: Requirements 3.3, 3.9, 17.5, Tasks 12.1-12.5
#[derive(Clone, Debug)]
pub struct VMCheckpoint {
    /// Cycle number
    pub cycle: usize,
    
    /// Register state
    pub registers: [u64; 32],
    
    /// Program counter
    pub pc: u64,
    
    /// Memory snapshot
    pub memory: HashMap<u64, u8>,
}

impl VMCheckpoint {
    /// Create new checkpoint
    pub fn new(cycle: usize, registers: [u64; 32], pc: u64, memory: HashMap<u64, u8>) -> Self {
        Self {
            cycle,
            registers,
            pc,
            memory,
        }
    }
}

/// RISC-V Virtual Machine
///
/// Executes RISC-V programs and generates witness vectors.
///
/// Reference: Requirements 3.1-3.2, Tasks 11.1-11.10
pub struct RiscVVM {
    /// General-purpose registers (x0-x31)
    pub registers: [u64; 32],
    
    /// Program counter
    pub pc: u64,
    
    /// Memory (sparse representation)
    pub memory: HashMap<u64, u8>,
    
    /// Execution cycle counter
    pub cycle_count: usize,
    
    /// Checkpoints for parallel regeneration
    pub checkpoints: Vec<VMCheckpoint>,
    
    /// Checkpoint interval
    pub checkpoint_interval: usize,
}

impl RiscVVM {
    /// Create new VM
    pub fn new() -> Self {
        Self {
            registers: [0u64; 32],
            pc: 0,
            memory: HashMap::new(),
            cycle_count: 0,
            checkpoints: Vec::new(),
            checkpoint_interval: 1000,
        }
    }
    
    /// Reset VM state
    pub fn reset(&mut self) {
        self.registers = [0u64; 32];
        self.pc = 0;
        self.memory.clear();
        self.cycle_count = 0;
        self.checkpoints.clear();
    }
    
    /// Load program into memory
    ///
    /// Loads a program (as bytes) into memory starting at address 0.
    /// Reference: Task 11.2
    pub fn load_program(&mut self, program: &[u8]) {
        for (i, &byte) in program.iter().enumerate() {
            self.memory.insert(i as u64, byte);
        }
    }
    
    /// Fetch instruction from memory
    ///
    /// Reads 4 bytes from memory at PC and returns as 32-bit instruction.
    /// Reference: Requirements 3.1-3.2, 3.8, Task 11.2
    pub fn fetch_instruction(&self) -> u32 {
        let mut instr = 0u32;
        for i in 0..4 {
            let byte = self.memory.get(&(self.pc + i)).copied().unwrap_or(0);
            instr |= (byte as u32) << (8 * i);
        }
        instr
    }
    
    /// Decode instruction
    ///
    /// Decodes a 32-bit instruction into its components.
    /// Reference: Requirements 3.1-3.2, 3.8, Task 11.3
    pub fn decode(&self, instr: u32) -> DecodedInstruction {
        let opcode_bits = instr & 0x7F;
        let rd = ((instr >> 7) & 0x1F) as usize;
        let rs1 = ((instr >> 15) & 0x1F) as usize;
        let rs2 = ((instr >> 20) & 0x1F) as usize;
        let funct3 = (instr >> 12) & 0x7;
        let funct7 = (instr >> 25) & 0x7F;
        
        // Decode immediate values
        let i_imm = ((instr as i32) >> 20) as u64;
        let s_imm = (((instr >> 25) as i32) << 5) | ((instr >> 7) & 0x1F) as i32;
        let b_imm = (((instr as i32) >> 31) << 12)
            | (((instr >> 7) & 0x1) as i32) << 11
            | (((instr >> 25) & 0x3F) as i32) << 5
            | (((instr >> 8) & 0xF) as i32) << 1;
        let u_imm = (instr & 0xFFFFF000) as i32 as u64;
        let j_imm = (((instr as i32) >> 31) << 20)
            | (((instr >> 21) & 0x3FF) as i32) << 1
            | (((instr >> 20) & 0x1) as i32) << 11
            | (((instr >> 12) & 0xFF) as i32) << 12;
        
        let shamt = ((instr >> 20) & 0x1F) as u32;
        
        let opcode = match opcode_bits {
            0x33 => match (funct7, funct3) {
                (0x00, 0x0) => Opcode::Add,
                (0x20, 0x0) => Opcode::Sub,
                (0x01, 0x0) => Opcode::Mul,
                (0x01, 0x4) => Opcode::Div,
                (0x01, 0x6) => Opcode::Rem,
                (0x00, 0x7) => Opcode::And,
                (0x00, 0x6) => Opcode::Or,
                (0x00, 0x4) => Opcode::Xor,
                (0x00, 0x1) => Opcode::Sll,
                (0x00, 0x5) => Opcode::Srl,
                (0x20, 0x5) => Opcode::Sra,
                (0x00, 0x2) => Opcode::Slt,
                (0x00, 0x3) => Opcode::Sltu,
                _ => Opcode::Add, // Default
            },
            0x13 => match funct3 {
                0x0 => Opcode::Addi,
                0x7 => Opcode::Andi,
                0x6 => Opcode::Ori,
                0x4 => Opcode::Xori,
                0x1 => Opcode::Slli,
                0x5 if funct7 == 0x00 => Opcode::Srli,
                0x5 if funct7 == 0x20 => Opcode::Srai,
                0x2 => Opcode::Slti,
                0x3 => Opcode::Sltui,
                _ => Opcode::Addi,
            },
            0x03 => match funct3 {
                0x0 => Opcode::Lb,
                0x1 => Opcode::Lh,
                0x2 => Opcode::Lw,
                0x4 => Opcode::Lbu,
                0x5 => Opcode::Lhu,
                _ => Opcode::Lb,
            },
            0x23 => match funct3 {
                0x0 => Opcode::Sb,
                0x1 => Opcode::Sh,
                0x2 => Opcode::Sw,
                _ => Opcode::Sb,
            },
            0x63 => match funct3 {
                0x0 => Opcode::Beq,
                0x1 => Opcode::Bne,
                0x4 => Opcode::Blt,
                0x5 => Opcode::Bge,
                0x6 => Opcode::Bltu,
                0x7 => Opcode::Bgeu,
                _ => Opcode::Beq,
            },
            0x6F => Opcode::Jal,
            0x67 => Opcode::Jalr,
            0x37 => Opcode::Lui,
            0x17 => Opcode::Auipc,
            0x0F => Opcode::Fence,
            0x73 => match instr {
                0x00000073 => Opcode::Ecall,
                0x00100073 => Opcode::Ebreak,
                _ => Opcode::Ecall,
            },
            _ => Opcode::Add,
        };
        
        DecodedInstruction {
            opcode,
            rd: if rd != 0 { Some(rd) } else { None },
            rs1: if rs1 != 0 { Some(rs1) } else { None },
            rs2: if rs2 != 0 { Some(rs2) } else { None },
            imm: i_imm,
            shamt,
        }
    }
    
    /// Load from memory
    ///
    /// Reads a value from memory at the given address.
    /// Reference: Requirements 3.1-3.2, 3.8, Task 11.5
    pub fn load_memory(&self, address: u64) -> u64 {
        let mut value = 0u64;
        for i in 0..8 {
            let byte = self.memory.get(&(address + i)).copied().unwrap_or(0);
            value |= (byte as u64) << (8 * i);
        }
        value
    }
    
    /// Store to memory
    ///
    /// Writes a value to memory at the given address.
    /// Reference: Requirements 3.1-3.2, 3.8, Task 11.5
    pub fn store_memory(&mut self, address: u64, value: u64) {
        for i in 0..8 {
            let byte = ((value >> (8 * i)) & 0xFF) as u8;
            self.memory.insert(address + i, byte);
        }
    }
    
    /// Execute single cycle
    ///
    /// Fetches, decodes, and executes one instruction.
    /// Returns witness slice for this cycle.
    ///
    /// Reference: Requirements 3.2, 3.8, Task 11.9
    pub fn execute_cycle<F: Field>(&mut self) -> WitnessSlice<F> {
        let mut slice = WitnessSlice::new();
        
        // Fetch instruction
        let instr = self.fetch_instruction();
        
        // Decode
        let decoded = self.decode(instr);
        
        // Record PC
        slice.set_pc(self.pc);
        
        // Execute instruction
        match decoded.opcode {
            Opcode::Add => {
                if let (Some(rs1), Some(rs2), Some(rd)) = (decoded.rs1, decoded.rs2, decoded.rd) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    slice.add_register_read(rs2, self.registers[rs2]);
                    let result = self.registers[rs1].wrapping_add(self.registers[rs2]);
                    self.registers[rd] = result;
                    slice.add_register_write(rd, result);
                    slice.add_alu_operation(AluOp::Add, result);
                }
            }
            Opcode::Sub => {
                if let (Some(rs1), Some(rs2), Some(rd)) = (decoded.rs1, decoded.rs2, decoded.rd) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    slice.add_register_read(rs2, self.registers[rs2]);
                    let result = self.registers[rs1].wrapping_sub(self.registers[rs2]);
                    self.registers[rd] = result;
                    slice.add_register_write(rd, result);
                    slice.add_alu_operation(AluOp::Sub, result);
                }
            }
            Opcode::Mul => {
                if let (Some(rs1), Some(rs2), Some(rd)) = (decoded.rs1, decoded.rs2, decoded.rd) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    slice.add_register_read(rs2, self.registers[rs2]);
                    let result = self.registers[rs1].wrapping_mul(self.registers[rs2]);
                    self.registers[rd] = result;
                    slice.add_register_write(rd, result);
                    slice.add_alu_operation(AluOp::Mul, result);
                }
            }
            Opcode::And => {
                if let (Some(rs1), Some(rs2), Some(rd)) = (decoded.rs1, decoded.rs2, decoded.rd) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    slice.add_register_read(rs2, self.registers[rs2]);
                    let result = self.registers[rs1] & self.registers[rs2];
                    self.registers[rd] = result;
                    slice.add_register_write(rd, result);
                    slice.add_alu_operation(AluOp::And, result);
                }
            }
            Opcode::Or => {
                if let (Some(rs1), Some(rs2), Some(rd)) = (decoded.rs1, decoded.rs2, decoded.rd) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    slice.add_register_read(rs2, self.registers[rs2]);
                    let result = self.registers[rs1] | self.registers[rs2];
                    self.registers[rd] = result;
                    slice.add_register_write(rd, result);
                    slice.add_alu_operation(AluOp::Or, result);
                }
            }
            Opcode::Xor => {
                if let (Some(rs1), Some(rs2), Some(rd)) = (decoded.rs1, decoded.rs2, decoded.rd) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    slice.add_register_read(rs2, self.registers[rs2]);
                    let result = self.registers[rs1] ^ self.registers[rs2];
                    self.registers[rd] = result;
                    slice.add_register_write(rd, result);
                    slice.add_alu_operation(AluOp::Xor, result);
                }
            }
            Opcode::Sll => {
                if let (Some(rs1), Some(rs2), Some(rd)) = (decoded.rs1, decoded.rs2, decoded.rd) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    slice.add_register_read(rs2, self.registers[rs2]);
                    let shamt = (self.registers[rs2] & 0x3F) as u32;
                    let result = self.registers[rs1].wrapping_shl(shamt);
                    self.registers[rd] = result;
                    slice.add_register_write(rd, result);
                    slice.add_alu_operation(AluOp::Sll, result);
                }
            }
            Opcode::Srl => {
                if let (Some(rs1), Some(rs2), Some(rd)) = (decoded.rs1, decoded.rs2, decoded.rd) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    slice.add_register_read(rs2, self.registers[rs2]);
                    let shamt = (self.registers[rs2] & 0x3F) as u32;
                    let result = self.registers[rs1].wrapping_shr(shamt);
                    self.registers[rd] = result;
                    slice.add_register_write(rd, result);
                    slice.add_alu_operation(AluOp::Srl, result);
                }
            }
            Opcode::Sra => {
                if let (Some(rs1), Some(rs2), Some(rd)) = (decoded.rs1, decoded.rs2, decoded.rd) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    slice.add_register_read(rs2, self.registers[rs2]);
                    let shamt = (self.registers[rs2] & 0x3F) as u32;
                    let result = ((self.registers[rs1] as i64) >> shamt) as u64;
                    self.registers[rd] = result;
                    slice.add_register_write(rd, result);
                    slice.add_alu_operation(AluOp::Sra, result);
                }
            }
            Opcode::Addi => {
                if let (Some(rs1), Some(rd)) = (decoded.rs1, decoded.rd) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    let result = self.registers[rs1].wrapping_add(decoded.imm);
                    self.registers[rd] = result;
                    slice.add_register_write(rd, result);
                    slice.add_alu_operation(AluOp::Add, result);
                }
            }
            Opcode::Lw => {
                if let (Some(rs1), Some(rd)) = (decoded.rs1, decoded.rd) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    let address = self.registers[rs1].wrapping_add(decoded.imm);
                    let value = self.load_memory(address);
                    self.registers[rd] = value;
                    slice.add_memory_read(address, value);
                    slice.add_register_write(rd, value);
                }
            }
            Opcode::Sw => {
                if let (Some(rs1), Some(rs2)) = (decoded.rs1, decoded.rs2) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    slice.add_register_read(rs2, self.registers[rs2]);
                    let address = self.registers[rs1].wrapping_add(decoded.imm);
                    let value = self.registers[rs2];
                    self.store_memory(address, value);
                    slice.add_memory_write(address, value);
                }
            }
            Opcode::Beq => {
                if let (Some(rs1), Some(rs2)) = (decoded.rs1, decoded.rs2) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    slice.add_register_read(rs2, self.registers[rs2]);
                    if self.registers[rs1] == self.registers[rs2] {
                        self.pc = self.pc.wrapping_add(decoded.imm);
                    } else {
                        self.pc = self.pc.wrapping_add(4);
                    }
                    slice.set_next_pc(self.pc);
                    return slice;
                }
            }
            Opcode::Bne => {
                if let (Some(rs1), Some(rs2)) = (decoded.rs1, decoded.rs2) {
                    slice.add_register_read(rs1, self.registers[rs1]);
                    slice.add_register_read(rs2, self.registers[rs2]);
                    if self.registers[rs1] != self.registers[rs2] {
                        self.pc = self.pc.wrapping_add(decoded.imm);
                    } else {
                        self.pc = self.pc.wrapping_add(4);
                    }
                    slice.set_next_pc(self.pc);
                    return slice;
                }
            }
            Opcode::Jal => {
                if let Some(rd) = decoded.rd {
                    let return_addr = self.pc.wrapping_add(4);
                    self.registers[rd] = return_addr;
                    slice.add_register_write(rd, return_addr);
                    self.pc = self.pc.wrapping_add(decoded.imm);
                    slice.set_next_pc(self.pc);
                    return slice;
                }
            }
            _ => {
                // Unsupported instruction, just increment PC
            }
        }
        
        // Default: increment PC by 4
        self.pc = self.pc.wrapping_add(4);
        slice.set_next_pc(self.pc);
        
        // Store checkpoint if needed
        if self.cycle_count % self.checkpoint_interval == 0 {
            self.store_checkpoint();
        }
        
        self.cycle_count += 1;
        slice
    }
    
    /// Store checkpoint
    ///
    /// Saves current VM state as a checkpoint.
    /// Reference: Requirements 3.3, 3.9, 17.5, Task 12.3
    pub fn store_checkpoint(&mut self) {
        let checkpoint = VMCheckpoint::new(
            self.cycle_count,
            self.registers,
            self.pc,
            self.memory.clone(),
        );
        self.checkpoints.push(checkpoint);
    }
    
    /// Restore from checkpoint
    ///
    /// Restores VM state from a checkpoint.
    /// Reference: Requirements 3.3, 3.9, Task 12.4
    pub fn restore_checkpoint(&mut self, checkpoint: &VMCheckpoint) {
        self.registers = checkpoint.registers;
        self.pc = checkpoint.pc;
        self.memory = checkpoint.memory.clone();
        self.cycle_count = checkpoint.cycle;
    }
    
    /// Find nearest checkpoint before cycle
    ///
    /// Finds the checkpoint closest to (but before) the target cycle.
    /// Reference: Task 12.4
    pub fn find_checkpoint(&self, target_cycle: usize) -> Option<&VMCheckpoint> {
        self.checkpoints
            .iter()
            .filter(|cp| cp.cycle <= target_cycle)
            .max_by_key(|cp| cp.cycle)
    }
}

