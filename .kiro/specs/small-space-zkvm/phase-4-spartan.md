# Phase 4: Spartan for Uniform R1CS - Implementation Spec

## Overview

Phase 4 implements the Spartan prover for Uniform R1CS constraints. This phase builds on the sum-check protocol (Phase 2) and streaming witness generation (Phase 3) to create a complete constraint system prover.

**Key Components:**
- R1CS structure module (Task 15)
- Spartan prover (Task 16)
- pcnext virtual polynomial (Task 17)
- Checkpoint (Task 18)

**Total Tasks:** 4 major tasks with 30+ sub-tasks
**Estimated Lines of Code:** 1500-2000 lines

## Task 15: Implement R1CS Structure Module

### 15.1 Implement SparseRow Structure
- Store indices: Vec<usize> (column indices)
- Store values: Vec<F> (field values)
- Implement efficient sparse row operations
- Support dot product with dense vectors
- **Requirements:** 4.1-4.2, 4.4

### 15.2 Implement ConstraintBlock Structure
- Store a_block: Vec<SparseRow> (A matrix rows)
- Store b_block: Vec<SparseRow> (B matrix rows)
- Store c_block: Vec<SparseRow> (C matrix rows)
- Each block has β constraints over O(1) variables
- **Requirements:** 4.1-4.2, 4.4

### 15.3 Implement UniformR1CS Structure
- Store num_constraints_per_cycle: usize (β)
- Store num_cycles: usize (T)
- Store constraint_block: ConstraintBlock (constant-sized blocks)
- Store num_variables: usize (total witness variables)
- **Requirements:** 4.1-4.2

### 15.4 Implement Matrix MLE Evaluation
- Evaluate Ã(Y,x), B̃(Y,x), C̃(Y,x) at point Y
- Use block-diagonal structure for O(log T) time
- Support streaming evaluation
- **Requirements:** 4.3, 4.10

### 15.5 Implement Streaming Matrix-Vector Product
- Stream Az, Bz, Cz while executing VM
- Compute block-by-block without storing full result
- Support on-demand computation
- **Requirements:** 4.3-4.4

### 15.6 Implement h̃_A Evaluation
- Compute h̃_A(Y) = Σ_x Ã(Y,x)·ũ(x)
- Stream through witness on-demand
- Support efficient computation
- **Requirements:** 4.3, 4.5

### 15.7 Implement h̃_B and h̃_C Evaluation
- Similar to h̃_A but for B and C matrices
- Use same streaming approach
- **Requirements:** 4.3, 4.5

## Task 16: Implement Spartan Prover

### 16.1 Implement SpartanProver Structure
- Store reference to UniformR1CS
- Store configuration parameters
- Store commitment scheme reference
- **Requirements:** 4.1-4.13

### 16.2 Implement First Sum-Check Oracle
- Create oracle for g(y) = eq̃(r_s, y)·(h̃_A(y)·h̃_B(y) - h̃_C(y))
- Implement query method that computes h̃ values on-demand
- Support efficient evaluation
- **Requirements:** 4.5, 4.8

### 16.3 Implement First Sum-Check Execution
- Prove q(S) = Σ_y eq̃(S,y)·(h̃_A(y)·h̃_B(y) - h̃_C(y)) = 0
- Use small-value sum-check optimization
- Extract challenges r_y
- **Requirements:** 4.5, 4.8, 4.11-4.13

### 16.4 Implement Second Sum-Check Oracle
- Create oracle for random linear combination:
- α·Ã(r_y,x)·ũ(x) + β·B̃(r_y,x)·ũ(x) + C̃(r_y,x)·ũ(x)
- Support efficient evaluation
- **Requirements:** 4.5, 4.9-4.10

### 16.5 Implement Second Sum-Check Execution
- Prove h̃_A(r_y), h̃_B(r_y), h̃_C(r_y) evaluations
- Use random linear combination for batching
- Extract challenges r_x
- **Requirements:** 4.5, 4.9-4.10

### 16.6 Implement Final Evaluation Computation
- Compute Ã(r_y, r_x), B̃(r_y, r_x), C̃(r_y, r_x)
- Use block-diagonal structure for O(log T) time
- Compute ũ(r_x) from witness
- **Requirements:** 4.5, 4.10

### 16.7 Implement Small-Value Optimization for Spartan
- Detect that h_A, h_B, h_C values are in {0,1,...,2^64-1}
- Use machine-word arithmetic for first rounds
- **Requirements:** 4.11-4.13

### 16.8 Track Spartan Performance
- Verify ~250T field operations in linear space
- Verify ~40T additional operations in small space
- **Requirements:** 4.12-4.13, 10.4

## Task 17: Implement pcnext Virtual Polynomial

### 17.1 Implement ShiftFunction Structure
- Store num_vars: usize (log T)
- Support efficient evaluation
- **Requirements:** 4.6-4.7

### 17.2 Implement h(r,j) Computation
- h(r,j) = (1-j₁)r₁·eq̃(j₂,...,j_{log T}, r₂,...,r_{log T})
- Return zero if j₁ = 1
- **Requirements:** 4.7, 17.14

### 17.3 Implement g(r,j) Computation
- g(r,j) = Σ_{k=1}^{log(T)-1} (∏ᵢ₌₁ᵏ jᵢ·(1-rᵢ))·(1-j_{k+1})r_{k+1}·eq̃(...)
- Check first k bits are all 1 and (k+1)-th bit is 0
- **Requirements:** 4.7, 17.14

### 17.4 Implement shift(r,j) Evaluation
- Combine h(r,j) + g(r,j)
- Evaluate in O(log T) time and O(1) space
- **Requirements:** 4.6-4.7

### 17.5 Implement Streaming Shift Evaluations
- Use depth-first traversal for h evaluations
- Use depth-first traversal for g evaluations
- Achieve O(T) time, O(log T) space
- **Requirements:** 4.7, 17.14, 17.18

### 17.6 Implement pcnext Oracle
- Create oracle for p̃cnext(r) = Σ_j shift(r,j)·p̃c(j)
- Use prefix-suffix structure (will be implemented in Phase 7)
- **Requirements:** 4.6-4.7

### 17.7 Implement pcnext-Evaluation Sum-Check
- Apply sum-check with prefix-suffix protocol
- Verify pcnext = shift * pc
- **Requirements:** 4.6-4.7

## Task 18: Checkpoint

- Ensure all tests pass
- Verify correctness of R1CS structure
- Verify Spartan prover correctness
- Verify pcnext virtual polynomial correctness
- Ask user if questions arise

## Implementation Order

1. **SparseRow and ConstraintBlock** (15.1-15.2)
   - Foundation for R1CS representation
   - Efficient sparse operations

2. **UniformR1CS Structure** (15.3)
   - Main constraint system representation
   - Block-diagonal structure

3. **Matrix Evaluation** (15.4-15.7)
   - MLE evaluation for matrices
   - Streaming computation

4. **SpartanProver Structure** (16.1)
   - Main prover structure
   - Configuration management

5. **Sum-Check Oracles** (16.2, 16.4)
   - First oracle for constraint checking
   - Second oracle for evaluation verification

6. **Sum-Check Execution** (16.3, 16.5)
   - Execute sum-check protocols
   - Extract challenges

7. **Final Evaluation** (16.6)
   - Compute final values
   - Verify constraints

8. **ShiftFunction** (17.1-17.4)
   - Virtual polynomial for pcnext
   - Efficient evaluation

9. **Streaming Shift** (17.5-17.7)
   - Streaming evaluation
   - Integration with sum-check

## Key Design Decisions

1. **Sparse Representation:** Use sparse rows for efficient storage and computation
2. **Block-Diagonal Structure:** Leverage constant-sized blocks for O(log T) evaluation
3. **Streaming Computation:** Compute h̃ values on-demand without storing full vectors
4. **Small-Value Optimization:** Use machine-word arithmetic for efficiency
5. **Modular Design:** Separate concerns into distinct structures and functions

## Testing Strategy

1. **Unit Tests:** Test each component independently
2. **Integration Tests:** Test Spartan prover with real constraints
3. **Property Tests:** Verify correctness properties
4. **Performance Tests:** Verify field operation counts
5. **Correctness Tests:** Compare with reference implementation

## Performance Targets

- **Linear-space Spartan:** ~250T field operations
- **Small-space Spartan:** ~290T field operations (250T + 40T overhead)
- **Slowdown factor:** ~1.16× (well under 2×)
- **Space complexity:** O(K + T^(1/2)) or O(K + log T)

## Dependencies

- Phase 1: Field arithmetic, MLE, equality functions, univariate polynomials
- Phase 2: Sum-check protocol (standard and small-space)
- Phase 3: Streaming witness generation
- Phase 7: Prefix-suffix protocol (for pcnext evaluation)

## Next Phase

Phase 5: Shout Protocol (Read-Only Memory) - Tasks 19-22
