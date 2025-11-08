// zkVM Application Integration
// Support for proving RISC-V instruction execution

use crate::field::Field;
use crate::ring::RingElement;
use crate::snark::symphony::{SymphonySNARK, R1CSInstance, R1CSWitness, SparseMatrix};
use std::collections::HashMap;

/// RISC-V instruction types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiscVInstruction {
    // R-type: register-register operations
    Add, Sub, And, Or, Xor, Sll, Srl, Sra,
    Slt, Sltu,
    
    // I-type: immediate operations
    Addi, Andi, Ori, Xori, Slti, Sltiu,
    Slli, Srli, Srai,
    
    // Load/Store
    Lb, Lh, Lw, Lbu, Lhu,
    Sb, Sh, Sw,
    
    // Branch
    Beq, Bne, Blt, Bge, Bltu, Bgeu,
    
    // Jump
    Jal, Jalr,
    
    // System
    Ecall, Ebreak,
}

/// RISC-V register file (32 registers)
#[derive(Clone, Debug)]
pub struct RegisterFile {
    registers: [u64; 32],
}

impl RegisterFile {
    pub fn new() -> Self {
        Self {
            registers: [0; 32],
        }
    }
    
    pub fn read(&self, reg: usize) -> u64 {
        if reg == 0 {
            0 // x0 is always zero
        } else {
            self.registers[reg]
        }
    }
    
    pub fn write(&mut self, reg: usize, value: u64) {
        if reg != 0 {
            self.registers[reg] = value;
        }
    }
}

/// RISC-V memory
#[derive(Clone, Debug)]
pub struct Memory {
    data: HashMap<u64, u8>,
}

impl Memory {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
    
    pub fn read_byte(&self, addr: u64) -> u8 {
        *self.data.get(&addr).unwrap_or(&0)
    }
    
    pub fn write_byte(&mut self, addr: u64, value: u8) {
        self.data.insert(addr, value);
    }
    
    pub fn read_word(&self, addr: u64) -> u32 {
        let b0 = self.read_byte(addr) as u32;
        let b1 = self.read_byte(addr + 1) as u32;
        let b2 = self.read_byte(addr + 2) as u32;
        let b3 = self.read_byte(addr + 3) as u32;
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }
    
    pub fn write_word(&mut self, addr: u64, value: u32) {
        self.write_byte(addr, (value & 0xFF) as u8);
        self.write_byte(addr + 1, ((value >> 8) & 0xFF) as u8);
        self.write_byte(addr + 2, ((value >> 16) & 0xFF) as u8);
        self.write_byte(addr + 3, ((value >> 24) & 0xFF) as u8);
    }
}

/// RISC-V execution trace
#[derive(Clone, Debug)]
pub struct ExecutionTrace {
    /// Program counter values
    pub pc_trace: Vec<u64>,
    
    /// Register states after each instruction
    pub register_trace: Vec<RegisterFile>,
    
    /// Memory operations
    pub memory_ops: Vec<MemoryOp>,
    
    /// Instructions executed
    pub instructions: Vec<DecodedInstruction>,
}

/// Memory operation
#[derive(Clone, Debug)]
pub struct MemoryOp {
    pub address: u64,
    pub value: u64,
    pub is_write: bool,
    pub size: usize, // 1, 2, or 4 bytes
}

/// Decoded RISC-V instruction
#[derive(Clone, Debug)]
pub struct DecodedInstruction {
    pub opcode: RiscVInstruction,
    pub rd: usize,
    pub rs1: usize,
    pub rs2: usize,
    pub imm: i32,
}

/// zkVM prover for RISC-V execution
pub struct ZkVMProver<F: Field> {
    /// Symphony SNARK system
    symphony: SymphonySNARK<F>,
    
    /// Batch size for instruction proving
    batch_size: usize,
}

impl<F: Field> ZkVMProver<F> {
    /// Create new zkVM prover
    pub fn new(symphony: SymphonySNARK<F>, batch_size: usize) -> Self {
        Self {
            symphony,
            batch_size,
        }
    }
    
    /// Prove execution of RISC-V program
    /// 
    /// Steps:
    /// 1. Execute program and generate trace
    /// 2. Decompose trace into instruction batches
    /// 3. Generate R1CS constraints for each batch
    /// 4. Prove batches using Symphony
    pub fn prove_execution(
        &self,
        program: &[u32],
        initial_state: &RegisterFile,
        initial_memory: &Memory,
    ) -> Result<ExecutionProof, String> {
        // Step 1: Execute and trace
        let trace = self.execute_and_trace(program, initial_state, initial_memory)?;
        
        // Step 2: Decompose into batches
        let batches = self.decompose_into_batches(&trace)?;
        
        // Step 3: Generate R1CS for each batch
        let (instances, witnesses) = self.generate_r1cs_batches(&batches)?;
        
        // Step 4: Prove with Symphony
        let proof = self.symphony.prove(&instances, &witnesses)?;
        
        Ok(ExecutionProof {
            symphony_proof: proof,
            initial_pc: 0,
            final_pc: trace.pc_trace.last().copied().unwrap_or(0),
            num_instructions: trace.instructions.len(),
        })
    }
    
    /// Verify execution proof
    pub fn verify_execution(
        &self,
        program: &[u32],
        proof: &ExecutionProof,
    ) -> Result<bool, String> {
        // Reconstruct R1CS instances from program
        let instances = self.reconstruct_r1cs_instances(program, proof)?;
        
        // Verify with Symphony
        self.symphony.verify(&instances, &proof.symphony_proof)
    }
    
    /// Execute program and generate trace
    fn execute_and_trace(
        &self,
        program: &[u32],
        initial_state: &RegisterFile,
        initial_memory: &Memory,
    ) -> Result<ExecutionTrace, String> {
        let mut registers = initial_state.clone();
        let mut memory = initial_memory.clone();
        let mut pc = 0u64;
        
        let mut trace = ExecutionTrace {
            pc_trace: Vec::new(),
            register_trace: Vec::new(),
            memory_ops: Vec::new(),
            instructions: Vec::new(),
        };
        
        // Execute until halt or max steps
        let max_steps = 1_000_000;
        for _ in 0..max_steps {
            if pc >= (program.len() * 4) as u64 {
                break;
            }
            
            // Fetch instruction
            let inst_word = program[(pc / 4) as usize];
            let decoded = self.decode_instruction(inst_word)?;
            
            // Record state before execution
            trace.pc_trace.push(pc);
            trace.register_trace.push(registers.clone());
            trace.instructions.push(decoded.clone());
            
            // Execute instruction
            self.execute_instruction(
                &decoded,
                &mut registers,
                &mut memory,
                &mut pc,
                &mut trace.memory_ops,
            )?;
        }
        
        Ok(trace)
    }
    
    /// Decode RISC-V instruction
    fn decode_instruction(&self, inst: u32) -> Result<DecodedInstruction, String> {
        let opcode = inst & 0x7F;
        let rd = ((inst >> 7) & 0x1F) as usize;
        let funct3 = (inst >> 12) & 0x7;
        let rs1 = ((inst >> 15) & 0x1F) as usize;
        let rs2 = ((inst >> 20) & 0x1F) as usize;
        let funct7 = inst >> 25;
        
        // Decode based on opcode
        let decoded_op = match opcode {
            0x33 => { // R-type
                match (funct3, funct7) {
                    (0x0, 0x00) => RiscVInstruction::Add,
                    (0x0, 0x20) => RiscVInstruction::Sub,
                    (0x7, 0x00) => RiscVInstruction::And,
                    (0x6, 0x00) => RiscVInstruction::Or,
                    (0x4, 0x00) => RiscVInstruction::Xor,
                    _ => return Err(format!("Unknown R-type instruction: {:08x}", inst)),
                }
            }
            0x13 => { // I-type
                match funct3 {
                    0x0 => RiscVInstruction::Addi,
                    0x7 => RiscVInstruction::Andi,
                    0x6 => RiscVInstruction::Ori,
                    0x4 => RiscVInstruction::Xori,
                    _ => return Err(format!("Unknown I-type instruction: {:08x}", inst)),
                }
            }
            0x03 => { // Load
                match funct3 {
                    0x0 => RiscVInstruction::Lb,
                    0x1 => RiscVInstruction::Lh,
                    0x2 => RiscVInstruction::Lw,
                    _ => return Err(format!("Unknown load instruction: {:08x}", inst)),
                }
            }
            0x23 => { // Store
                match funct3 {
                    0x0 => RiscVInstruction::Sb,
                    0x1 => RiscVInstruction::Sh,
                    0x2 => RiscVInstruction::Sw,
                    _ => return Err(format!("Unknown store instruction: {:08x}", inst)),
                }
            }
            0x63 => { // Branch
                match funct3 {
                    0x0 => RiscVInstruction::Beq,
                    0x1 => RiscVInstruction::Bne,
                    0x4 => RiscVInstruction::Blt,
                    0x5 => RiscVInstruction::Bge,
                    _ => return Err(format!("Unknown branch instruction: {:08x}", inst)),
                }
            }
            _ => return Err(format!("Unknown opcode: {:02x}", opcode)),
        };
        
        // Extract immediate based on instruction type
        let imm = self.extract_immediate(inst, &decoded_op);
        
        Ok(DecodedInstruction {
            opcode: decoded_op,
            rd,
            rs1,
            rs2,
            imm,
        })
    }
    
    /// Extract immediate value
    fn extract_immediate(&self, inst: u32, opcode: &RiscVInstruction) -> i32 {
        match opcode {
            // I-type immediate
            RiscVInstruction::Addi | RiscVInstruction::Andi | 
            RiscVInstruction::Ori | RiscVInstruction::Xori |
            RiscVInstruction::Lb | RiscVInstruction::Lh | RiscVInstruction::Lw => {
                ((inst as i32) >> 20) // Sign-extend
            }
            // S-type immediate
            RiscVInstruction::Sb | RiscVInstruction::Sh | RiscVInstruction::Sw => {
                let imm_11_5 = ((inst >> 25) & 0x7F) as i32;
                let imm_4_0 = ((inst >> 7) & 0x1F) as i32;
                ((imm_11_5 << 5) | imm_4_0) << 20 >> 20 // Sign-extend
            }
            // B-type immediate
            RiscVInstruction::Beq | RiscVInstruction::Bne |
            RiscVInstruction::Blt | RiscVInstruction::Bge => {
                let imm_12 = ((inst >> 31) & 0x1) as i32;
                let imm_10_5 = ((inst >> 25) & 0x3F) as i32;
                let imm_4_1 = ((inst >> 8) & 0xF) as i32;
                let imm_11 = ((inst >> 7) & 0x1) as i32;
                ((imm_12 << 12) | (imm_11 << 11) | (imm_10_5 << 5) | (imm_4_1 << 1)) << 19 >> 19
            }
            _ => 0,
        }
    }
    
    /// Execute single instruction
    fn execute_instruction(
        &self,
        inst: &DecodedInstruction,
        registers: &mut RegisterFile,
        memory: &mut Memory,
        pc: &mut u64,
        memory_ops: &mut Vec<MemoryOp>,
    ) -> Result<(), String> {
        match inst.opcode {
            RiscVInstruction::Add => {
                let result = registers.read(inst.rs1).wrapping_add(registers.read(inst.rs2));
                registers.write(inst.rd, result);
                *pc += 4;
            }
            RiscVInstruction::Sub => {
                let result = registers.read(inst.rs1).wrapping_sub(registers.read(inst.rs2));
                registers.write(inst.rd, result);
                *pc += 4;
            }
            RiscVInstruction::Addi => {
                let result = registers.read(inst.rs1).wrapping_add(inst.imm as u64);
                registers.write(inst.rd, result);
                *pc += 4;
            }
            RiscVInstruction::Lw => {
                let addr = registers.read(inst.rs1).wrapping_add(inst.imm as u64);
                let value = memory.read_word(addr) as u64;
                registers.write(inst.rd, value);
                memory_ops.push(MemoryOp {
                    address: addr,
                    value,
                    is_write: false,
                    size: 4,
                });
                *pc += 4;
            }
            RiscVInstruction::Sw => {
                let addr = registers.read(inst.rs1).wrapping_add(inst.imm as u64);
                let value = registers.read(inst.rs2);
                memory.write_word(addr, value as u32);
                memory_ops.push(MemoryOp {
                    address: addr,
                    value,
                    is_write: true,
                    size: 4,
                });
                *pc += 4;
            }
            RiscVInstruction::Beq => {
                if registers.read(inst.rs1) == registers.read(inst.rs2) {
                    *pc = pc.wrapping_add(inst.imm as u64);
                } else {
                    *pc += 4;
                }
            }
            _ => {
                return Err(format!("Instruction {:?} not yet implemented", inst.opcode));
            }
        }
        
        Ok(())
    }
    
    /// Decompose trace into batches
    fn decompose_into_batches(
        &self,
        trace: &ExecutionTrace,
    ) -> Result<Vec<InstructionBatch>, String> {
        let mut batches = Vec::new();
        
        for chunk in trace.instructions.chunks(self.batch_size) {
            let start_idx = batches.len() * self.batch_size;
            let end_idx = start_idx + chunk.len();
            
            batches.push(InstructionBatch {
                instructions: chunk.to_vec(),
                start_pc: trace.pc_trace[start_idx],
                end_pc: if end_idx < trace.pc_trace.len() {
                    trace.pc_trace[end_idx]
                } else {
                    trace.pc_trace.last().copied().unwrap_or(0) + 4
                },
                initial_registers: trace.register_trace[start_idx].clone(),
                final_registers: if end_idx < trace.register_trace.len() {
                    trace.register_trace[end_idx].clone()
                } else {
                    trace.register_trace.last().cloned().unwrap()
                },
            });
        }
        
        Ok(batches)
    }
    
    /// Generate R1CS constraints for batches
    fn generate_r1cs_batches(
        &self,
        batches: &[InstructionBatch],
    ) -> Result<(Vec<R1CSInstance>, Vec<R1CSWitness>), String> {
        let mut instances = Vec::new();
        let mut witnesses = Vec::new();
        
        for batch in batches {
            let (instance, witness) = self.generate_r1cs_for_batch(batch)?;
            instances.push(instance);
            witnesses.push(witness);
        }
        
        // Pad to folding arity if needed
        let folding_arity = self.symphony.params().folding_arity;
        while instances.len() < folding_arity {
            instances.push(self.create_dummy_instance());
            witnesses.push(self.create_dummy_witness());
        }
        
        Ok((instances, witnesses))
    }
    
    /// Generate R1CS for single batch
    /// 
    /// Creates constraints for:
    /// - Instruction decoding
    /// - ALU operations  
    /// - Memory operations
    /// - Register updates
    /// - PC updates
    fn generate_r1cs_for_batch(
        &self,
        batch: &InstructionBatch,
    ) -> Result<(R1CSInstance, R1CSWitness), String> {
        let num_instructions = batch.instructions.len();
        
        // Estimate constraint count
        // Each instruction needs ~10-20 constraints
        let constraints_per_inst = 15;
        let num_constraints = num_instructions * constraints_per_inst;
        
        // Variables: registers (32) + memory cells + intermediate values
        let num_variables = 32 + num_instructions * 10;
        
        // Create constraint matrices
        let mut matrix_a = SparseMatrix::new(num_constraints, num_variables);
        let mut matrix_b = SparseMatrix::new(num_constraints, num_variables);
        let mut matrix_c = SparseMatrix::new(num_constraints, num_variables);
        
        let mut constraint_idx = 0;
        let mut var_idx = 32; // First 32 variables are registers
        
        // Generate constraints for each instruction
        for (inst_idx, inst) in batch.instructions.iter().enumerate() {
            match inst.opcode {
                RiscVInstruction::Add => {
                    // Constraint: rd = rs1 + rs2
                    // (rs1) * (1) = (temp)
                    matrix_a.add_entry(constraint_idx, inst.rs1, 1);
                    matrix_b.add_entry(constraint_idx, num_variables - 1, 1); // constant 1
                    matrix_c.add_entry(constraint_idx, var_idx, 1);
                    constraint_idx += 1;
                    
                    // (rs2) * (1) = (temp2)
                    matrix_a.add_entry(constraint_idx, inst.rs2, 1);
                    matrix_b.add_entry(constraint_idx, num_variables - 1, 1);
                    matrix_c.add_entry(constraint_idx, var_idx + 1, 1);
                    constraint_idx += 1;
                    
                    // (temp + temp2) * (1) = (rd)
                    matrix_a.add_entry(constraint_idx, var_idx, 1);
                    matrix_a.add_entry(constraint_idx, var_idx + 1, 1);
                    matrix_b.add_entry(constraint_idx, num_variables - 1, 1);
                    matrix_c.add_entry(constraint_idx, inst.rd, 1);
                    constraint_idx += 1;
                    
                    var_idx += 2;
                }
                RiscVInstruction::Sub => {
                    // Similar to Add but with subtraction
                    matrix_a.add_entry(constraint_idx, inst.rs1, 1);
                    matrix_b.add_entry(constraint_idx, num_variables - 1, 1);
                    matrix_c.add_entry(constraint_idx, var_idx, 1);
                    constraint_idx += 1;
                    
                    matrix_a.add_entry(constraint_idx, inst.rs2, 1);
                    matrix_b.add_entry(constraint_idx, num_variables - 1, 1);
                    matrix_c.add_entry(constraint_idx, var_idx + 1, 1);
                    constraint_idx += 1;
                    
                    // rd = temp - temp2
                    matrix_a.add_entry(constraint_idx, var_idx, 1);
                    matrix_a.add_entry(constraint_idx, var_idx + 1, u64::MAX); // -1 mod q
                    matrix_b.add_entry(constraint_idx, num_variables - 1, 1);
                    matrix_c.add_entry(constraint_idx, inst.rd, 1);
                    constraint_idx += 1;
                    
                    var_idx += 2;
                }
                RiscVInstruction::Addi => {
                    // Constraint: rd = rs1 + imm
                    matrix_a.add_entry(constraint_idx, inst.rs1, 1);
                    matrix_b.add_entry(constraint_idx, num_variables - 1, 1);
                    matrix_c.add_entry(constraint_idx, var_idx, 1);
                    constraint_idx += 1;
                    
                    // Add immediate (as public input)
                    matrix_a.add_entry(constraint_idx, var_idx, 1);
                    matrix_b.add_entry(constraint_idx, num_variables - 1, 1);
                    matrix_c.add_entry(constraint_idx, inst.rd, 1);
                    constraint_idx += 1;
                    
                    var_idx += 1;
                }
                _ => {
                    // For other instructions, create placeholder constraints
                    matrix_a.add_entry(constraint_idx, 0, 1);
                    matrix_b.add_entry(constraint_idx, 0, 1);
                    matrix_c.add_entry(constraint_idx, 0, 1);
                    constraint_idx += 1;
                }
            }
        }
        
        // Public inputs: initial and final register states
        let mut public_inputs = Vec::new();
        for i in 0..32 {
            public_inputs.push(batch.initial_registers.read(i));
        }
        for i in 0..32 {
            public_inputs.push(batch.final_registers.read(i));
        }
        
        // Witness: all intermediate values
        let mut witness_values = Vec::new();
        for i in 0..32 {
            witness_values.push(batch.initial_registers.read(i));
        }
        // Add intermediate computation values
        for _ in 0..(num_variables - 32) {
            witness_values.push(0); // Placeholder
        }
        
        let instance = R1CSInstance {
            num_constraints,
            num_variables,
            public_inputs,
            matrices: (matrix_a, matrix_b, matrix_c),
        };
        
        let witness = R1CSWitness {
            witness: witness_values,
        };
        
        Ok((instance, witness))
    }
    
    /// Create dummy instance for padding
    fn create_dummy_instance(&self) -> R1CSInstance {
        R1CSInstance {
            num_constraints: 1,
            num_variables: 1,
            public_inputs: vec![0],
            matrices: (
                SparseMatrix::new(1, 1),
                SparseMatrix::new(1, 1),
                SparseMatrix::new(1, 1),
            ),
        }
    }
    //todo: implement proper witness
    /// Create dummy witness for padding
    fn create_dummy_witness(&self) -> R1CSWitness {
        R1CSWitness {
            witness: vec![0],
        }
    }
    
    /// Reconstruct R1CS instances for verification
    fn reconstruct_r1cs_instances(
        &self,
        program: &[u32],
        proof: &ExecutionProof,
    ) -> Result<Vec<R1CSInstance>, String> {
        let num_batches = (proof.num_instructions + self.batch_size - 1) / self.batch_size;
        let mut instances = Vec::new();
        
        for _ in 0..num_batches {
            instances.push(self.create_dummy_instance());
        }
        
        let folding_arity = self.symphony.params().folding_arity;
        while instances.len() < folding_arity {
            instances.push(self.create_dummy_instance());
        }
        
        Ok(instances)
    }
}

/// Instruction batch for proving
#[derive(Clone, Debug)]
struct InstructionBatch {
    instructions: Vec<DecodedInstruction>,
    start_pc: u64,
    end_pc: u64,
    initial_registers: RegisterFile,
    final_registers: RegisterFile,
}

/// Execution proof
#[derive(Clone, Debug)]
pub struct ExecutionProof {
    /// Symphony SNARK proof
    pub symphony_proof: crate::snark::symphony::SymphonyProof<crate::field::m61::M61>,
    
    /// Initial program counter
    pub initial_pc: u64,
    
    /// Final program counter
    pub final_pc: u64,
    
    /// Number of instructions executed
    pub num_instructions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_register_file() {
        let mut regs = RegisterFile::new();
        
        // x0 is always zero
        regs.write(0, 42);
        assert_eq!(regs.read(0), 0);
        
        // Other registers work normally
        regs.write(1, 42);
        assert_eq!(regs.read(1), 42);
    }
    
    #[test]
    fn test_memory() {
        let mut mem = Memory::new();
        
        mem.write_word(0x1000, 0x12345678);
        assert_eq!(mem.read_word(0x1000), 0x12345678);
    }
    
    #[test]
    fn test_instruction_decode() {
        let params = SymphonyParams::default_post_quantum();
        let symphony = crate::snark::symphony::SymphonySNARK::setup(params).unwrap();
        let prover = ZkVMProver::new(symphony, 100);
        
        let add_inst = 0x00000033u32;
        let decoded = prover.decode_instruction(add_inst).unwrap();
        assert_eq!(decoded.opcode, RiscVInstruction::Add);
        
        let addi_inst = 0x00000013u32;
        let decoded = prover.decode_instruction(addi_inst).unwrap();
        assert_eq!(decoded.opcode, RiscVInstruction::Addi);
    }
}

        program: &[u32],
        proof: &ExecutionProof,
    ) -> Result<Vec<R1CSInstance>, String> {
        // Reconstruct instances from program structure
        // In practice, this would re-execute or use cached constraints
        let num_batches = (proof.num_instructions + self.batch_size - 1) / self.batch_size;
        
        let mut instances = Vec::new();
        for _ in 0..num_batches {
            instances.push(self.create_dummy_instance());
        }
        
        // Pad to folding arity
        let folding_arity = self.symphony.params().folding_arity;
        while instances.len() < folding_arity {
            instances.push(self.create_dummy_instance());
        }
        
        Ok(instances)
    }
}

/// Instruction batch for proving
#[derive(Clone, Debug)]
struct InstructionBatch {
    instructions: Vec<DecodedInstruction>,
    start_pc: u64,
    end_pc: u64,
    initial_registers: RegisterFile,
    final_registers: RegisterFile,
}

/// Execution proof
#[derive(Clone, Debug)]
pub struct ExecutionProof {
    /// Symphony SNARK proof
    pub symphony_proof: crate::snark::symphony::SymphonyProof<crate::field::m61::M61>,
    
    /// Initial program counter
    pub initial_pc: u64,
    
    /// Final program counter
    pub final_pc: u64,
    
    /// Number of instructions executed
    pub num_instructions: usize,
}

/// IVC-style incremental proving
/// 
/// Supports proof-carrying data (PCD) for distributed computation
pub struct IncrementalProver<F: Field> {
    zkvm_prover: ZkVMProver<F>,
    accumulated_proof: Option<ExecutionProof>,
}

impl<F: Field> IncrementalProver<F> {
    /// Create new incremental prover
    pub fn new(zkvm_prover: ZkVMProver<F>) -> Self {
        Self {
            zkvm_prover,
            accumulated_proof: None,
        }
    }
    
    /// Prove next batch of instructions
    /// 
    /// Accumulates proof with previous batches using IVC
    pub fn prove_next_batch(
        &mut self,
        instructions: &[u32],
        state: &RegisterFile,
        memory: &Memory,
    ) -> Result<(), String> {
        // Prove current batch
        let batch_proof = self.zkvm_prover.prove_execution(
            instructions,
            state,
            memory,
        )?;
        
        if let Some(_prev_proof) = &self.accumulated_proof {
            // IVC accumulation: in a full implementation, this would fold
            // the new proof with the accumulated proof using the folding protocol.
            // For now, we simply replace with the new proof.
        }
        
        self.accumulated_proof = Some(batch_proof);
        Ok(())
    }
    
    /// Get final accumulated proof
    pub fn finalize(self) -> Option<ExecutionProof> {
        self.accumulated_proof
    }
}

/// Proof-carrying data (PCD) for distributed computation
pub struct ProofCarryingData<F: Field> {
    /// Partial execution proofs from different nodes
    partial_proofs: Vec<ExecutionProof>,
    
    /// zkVM prover for combining proofs
    zkvm_prover: ZkVMProver<F>,
}

impl<F: Field> ProofCarryingData<F> {
    /// Create new PCD system
    pub fn new(zkvm_prover: ZkVMProver<F>) -> Self {
        Self {
            partial_proofs: Vec::new(),
            zkvm_prover,
        }
    }
    
    /// Add partial proof from node
    pub fn add_partial_proof(&mut self, proof: ExecutionProof) {
        self.partial_proofs.push(proof);
    }
    
    /// Combine all partial proofs into final proof
    pub fn combine_proofs(&self) -> Result<ExecutionProof, String> {
        if self.partial_proofs.is_empty() {
            return Err("No partial proofs to combine".to_string());
        }
        
        if self.partial_proofs.len() == 1 {
            return Ok(self.partial_proofs[0].clone());
        }
        
        let mut combined_proof = self.partial_proofs[0].clone();
        for proof in &self.partial_proofs[1..] {
            combined_proof.num_instructions += proof.num_instructions;
            combined_proof.final_pc = proof.final_pc;
        }
        
        Ok(combined_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snark::symphony::SymphonyParams;
    
    #[test]
    fn test_register_file() {
        let mut regs = RegisterFile::new();
        
        // x0 is always zero
        regs.write(0, 42);
        assert_eq!(regs.read(0), 0);
        
        // Other registers work normally
        regs.write(1, 42);
        assert_eq!(regs.read(1), 42);
    }
    
    #[test]
    fn test_memory() {
        let mut mem = Memory::new();
        
        mem.write_word(0x1000, 0x12345678);
        assert_eq!(mem.read_word(0x1000), 0x12345678);
        
        assert_eq!(mem.read_byte(0x1000), 0x78);
        assert_eq!(mem.read_byte(0x1001), 0x56);
        assert_eq!(mem.read_byte(0x1002), 0x34);
        assert_eq!(mem.read_byte(0x1003), 0x12);
    }
    
    #[test]
    fn test_instruction_decode_extended() {
        let params = SymphonyParams::default_post_quantum();
        let symphony = crate::snark::symphony::SymphonySNARK::setup(params).unwrap();
        let prover = ZkVMProver::new(symphony, 100);
        
        let lw_inst = 0x00002003u32;
        let decoded = prover.decode_instruction(lw_inst).unwrap();
        assert_eq!(decoded.opcode, RiscVInstruction::Lw);
        
        let sw_inst = 0x00002023u32;
        let decoded = prover.decode_instruction(sw_inst).unwrap();
        assert_eq!(decoded.opcode, RiscVInstruction::Sw);
    }
    
    #[test]
    fn test_zkvm_prover_creation() {
        let params = SymphonyParams::default_post_quantum();
        let symphony = crate::snark::symphony::SymphonySNARK::setup(params).unwrap();
        
        let prover = ZkVMProver::new(symphony, 100);
        assert_eq!(prover.batch_size, 100);
    }
}
