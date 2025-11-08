# HyperWolf PCS Design Document

## Overview

This design document describes the integration of HyperWolf polynomial commitment scheme with the existing Neo-LatticeFold+ zkVM implementation and Symphony SNARK framework. HyperWolf provides a lattice-based PCS with logarithmic verification time, sub-logarithmic proof size, and exact ℓ₂-soundness under standard M-SIS assumptions.

### Key Design Goals

1. **Unified PCS Backend**: Replace or augment existing commitment schemes with HyperWolf for improved verification efficiency
2. **Standard Soundness**: Achieve exact ℓ₂-norm extraction without relaxation factors
3. **Symphony Integration**: Use HyperWolf as the polynomial commitment layer for Symphony's high-arity folding
4. **Neo Compatibility**: Integrate with Neo's pay-per-bit commitments and CCS folding
5. **LatticeFold+ Synergy**: Combine HyperWolf's evaluation proofs with LatticeFold+'s folding techniques
6. **Modular Architecture**: Design clean interfaces that allow switching between commitment schemes

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  (zkVM, Smart Contracts, Verifiable Computation)            │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                   Symphony SNARK Layer                       │
│  - High-arity folding (arity 2^κ)                           │
│  - CCS relation handling                                     │
│  - Fiat-Shamir transformation                               │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│              HyperWolf PCS Layer (NEW)                       │
│  - k-round witness folding                                   │
│  - Guarded IPA for exact ℓ₂-soundness                       │
│  - LaBRADOR compression                                      │
│  - Batching support                                          │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│           Neo/LatticeFold+ Folding Layer                     │
│  - CCS folding schemes                                       │
│  - Pay-per-bit commitments                                   │
│  - Two-layer folding                                         │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│              Lattice Primitives Layer                        │
│  - Ring operations (Rq = Zq[X]/(X^d + 1))                   │
│  - M-SIS assumption                                          │
│  - Gadget decomposition                                      │
│  - NTT for polynomial multiplication                         │
└─────────────────────────────────────────────────────────────┘
```

## Architecture

### Component Hierarchy

```
neo-lattice-zkvm/
├── src/
│   ├── commitment/
│   │   ├── hyperwolf/           # NEW: HyperWolf PCS implementation
│   │   │   ├── mod.rs            # Main PCS interface
│   │   │   ├── core_protocol.rs # k-round witness folding
│   │   │   ├── guarded_ipa.rs   # Exact ℓ₂-norm proof
│   │   │   ├── leveled_commit.rs # Hierarchical commitments
│   │   │   ├── labrador.rs      # LaBRADOR compression
│   │   │   ├── batching.rs      # Batching techniques
│   │   │   └── params.rs        # Parameter selection
│   │   ├── ajtai.rs             # EXISTING: Base Ajtai commitments
│   │   ├── neo_payperbit.rs     # EXISTING: Neo pay-per-bit
│   │   └── mod.rs               # Unified commitment interface
│   ├── ring/
│   │   ├── tensor.rs            # ENHANCED: k-dimensional tensors
│   │   ├── decomposition.rs     # ENHANCED: Gadget decomposition
│   │   └── ...
│   ├── protocols/
│   │   ├── hyperwolf_eval.rs    # NEW: HyperWolf evaluation protocol
│   │   └── ...
│   ├── snark/
│   │   ├── symphony.rs          # ENHANCED: Symphony with HyperWolf
│   │   └── ...
│   └── folding/
│       ├── hyperwolf_fold.rs    # NEW: Folding with HyperWolf
│       └── ...
```


## Components and Interfaces

### 1. Core HyperWolf PCS Interface

```rust
/// Main polynomial commitment scheme interface for HyperWolf
pub trait HyperWolfPCS<F: Field, R: Ring> {
    type Commitment;
    type Proof;
    type PublicParams;
    type EvalPoint;
    
    /// Setup: Generate public parameters
    /// Returns pp = ((A_i ∈ R_q^{κ×2κι})_{i∈[1,k-1]}, A_0 ∈ R_q^{κ×2ι})
    fn setup(
        security_param: usize,  // λ = 128
        degree_bound: usize,    // N
        ring_dim: usize,        // d = 64
    ) -> Result<Self::PublicParams, Error>;
    
    /// Commit to polynomial f
    /// For univariate: f(X) = Σ_{i=0}^{N-1} f_i X^i
    /// For multilinear: f(X_0,...,X_{ℓ-1}) = Σ coefficients
    /// Returns cm = F_{k-1,0}(s⃗) where s⃗ = G^{-1}_{b,N/d}(MR(f⃗))
    fn commit(
        pp: &Self::PublicParams,
        polynomial: &Polynomial<F>,
    ) -> Result<(Self::Commitment, CommitmentState), Error>;
    
    /// Open commitment to verify f
    fn open(
        pp: &Self::PublicParams,
        commitment: &Self::Commitment,
        polynomial: &Polynomial<F>,
        state: &CommitmentState,
    ) -> Result<bool, Error>;
    
    /// Prove evaluation: f(u) = v or f(u⃗) = v
    /// Runs k-round protocol with witness folding
    fn prove_eval(
        pp: &Self::PublicParams,
        commitment: &Self::Commitment,
        polynomial: &Polynomial<F>,
        eval_point: &Self::EvalPoint,
        eval_value: &F,
        state: &CommitmentState,
    ) -> Result<Self::Proof, Error>;
    
    /// Verify evaluation proof
    fn verify_eval(
        pp: &Self::PublicParams,
        commitment: &Self::Commitment,
        eval_point: &Self::EvalPoint,
        eval_value: &F,
        proof: &Self::Proof,
    ) -> Result<bool, Error>;
    
    /// Batch prove multiple evaluations
    fn batch_prove(
        pp: &Self::PublicParams,
        claims: &[EvaluationClaim<F>],
    ) -> Result<Self::Proof, Error>;
    
    /// Batch verify multiple evaluations
    fn batch_verify(
        pp: &Self::PublicParams,
        claims: &[EvaluationClaim<F>],
        proof: &Self::Proof,
    ) -> Result<bool, Error>;
}

/// Evaluation claim for batching
pub struct EvaluationClaim<F: Field> {
    pub commitment: Commitment,
    pub polynomial: Option<Polynomial<F>>,  // For prover
    pub eval_point: EvalPoint,
    pub eval_value: F,
}
```

### 2. Core Protocol Components

#### 2.1 Witness Tensor Reshaping

```rust
/// k-dimensional tensor for witness folding
pub struct WitnessTensor<R: Ring> {
    /// Tensor data in row-major order
    data: Vec<R>,
    /// Shape: (b_{k-1}, ..., b_1, b_0) where N = ∏ b_i
    shape: Vec<usize>,
    /// Dimension k
    arity: usize,
}

impl<R: Ring> WitnessTensor<R> {
    /// Reshape vector s⃗ ∈ R_q^n into k-dimensional tensor
    /// where n = Nι/d = 2^k ι
    pub fn from_vector(
        witness: Vec<R>,
        arity: usize,
    ) -> Result<Self, Error>;
    
    /// Tensor-vector product: f^(k) · a⃗
    /// Computes Σ_{i=0}^{b_0-1} a_i f_i^(k) ∈ R_q^{b_{k-1}×...×b_2×b_1}
    pub fn tensor_vector_product(
        &self,
        vector: &[R],
    ) -> Result<Self, Error>;
    
    /// Vector-tensor product: c⃗^⊤ · f^(k)
    /// Computes Σ_{i=0}^{b_{k-1}-1} c_i f_i^(k-1) ∈ R_q^{b_{k-2}×...×b_1×b_0}
    pub fn vector_tensor_product(
        vector: &[R],
        &self,
    ) -> Result<Self, Error>;
    
    /// Split tensor along first dimension into left and right halves
    pub fn split(&self) -> (Self, Self);
    
    /// Fold tensor: c_0 · left + c_1 · right
    pub fn fold(
        left: &Self,
        right: &Self,
        challenge: &[R; 2],
    ) -> Result<Self, Error>;
}
```

#### 2.2 Guarded Inner-Product Argument

```rust
/// Guarded IPA for exact ℓ₂-soundness
pub struct GuardedIPA<R: Ring> {
    /// IPA for ⟨s⃗, σ^{-1}(s⃗)⟩ mod q = b
    ipa_proof: Vec<IPARound<R>>,
    /// Final witness for smallness check
    final_witness: Vec<R>,
}

pub struct IPARound<R: Ring> {
    /// L_i = ⟨s⃗_{i,L}, σ^{-1}(s⃗_{i,L})⟩
    pub L: R,
    /// M_i = ⟨s⃗_{i,L}, σ^{-1}(s⃗_{i,R})⟩
    pub M: R,
    /// R_i = ⟨s⃗_{i,R}, σ^{-1}(s⃗_{i,R})⟩
    pub R: R,
}

impl<R: Ring> GuardedIPA<R> {
    /// Prove ∥s⃗∥₂² = b with exact ℓ₂-soundness
    /// Proves: (i) ct(⟨s⃗, σ^{-1}(s⃗)⟩) mod q = b
    ///         (ii) ∥s⃗∥_∞ ≤ β₂ < q/√(nd)
    pub fn prove(
        witness: &[R],
        norm_bound_squared: &R::BaseField,
        infinity_bound: &R::BaseField,
    ) -> Result<Self, Error>;
    
    /// Verify guarded IPA proof
    /// Checks both IPA relation and smallness guard
    pub fn verify(
        &self,
        claimed_norm_squared: &R::BaseField,
        infinity_bound: &R::BaseField,
        challenges: &[Challenge<R>],
    ) -> Result<bool, Error>;
    
    /// Check final witness satisfies ∥s⃗^(1)∥_∞ ≤ γ
    /// where γ = (2T)^{k-1} β₂
    fn check_smallness_guard(
        &self,
        gamma: &R::BaseField,
    ) -> bool;
}
```

#### 2.3 Leveled Ajtai Commitment

```rust
/// Leveled commitment structure F_{k-1,0}(s⃗)
pub struct LeveledCommitment<R: Ring> {
    /// Commitment value
    pub value: Vec<R>,
    /// Level in hierarchy (0 to k-1)
    pub level: usize,
    /// Decomposition proof for verification
    pub decomposition: Vec<R>,
}

impl<R: Ring> LeveledCommitment<R> {
    /// Compute F_{i,j}(s⃗) recursively
    /// F_{i,j}(s⃗) = {
    ///   A_i s⃗ mod q                                    if i = j,
    ///   F_{i,j+1}(G^{-1}_{b,M_{i,j}κ}((I_{M_{i,j}} ⊗ A_j) · G^{-1}_{b,N}(s⃗)))  if i > j
    /// }
    pub fn compute(
        witness: &[R],
        matrices: &[Matrix<R>],
        level_i: usize,
        level_j: usize,
    ) -> Result<Self, Error>;
    
    /// Verify commitment consistency in round i
    /// Checks: A_{k-i-1} π⃗_{cm,i} = [c_{k-i,0}G^κ  c_{k-i,1}G^κ] π⃗_{cm,i-1}
    pub fn verify_round(
        &self,
        prev_commitment: &Self,
        challenge: &[R; 2],
        matrix: &Matrix<R>,
    ) -> Result<bool, Error>;
}
```


#### 2.4 k-Round Evaluation Protocol

```rust
/// Complete k-round evaluation proof
pub struct HyperWolfProof<R: Ring> {
    /// Evaluation proofs for k-1 rounds
    eval_proofs: Vec<EvalRound<R>>,
    /// Norm proofs for k-1 rounds (guarded IPA)
    norm_proofs: Vec<IPARound<R>>,
    /// Commitment proofs for k-1 rounds
    commitment_proofs: Vec<CommitmentRound<R>>,
    /// Final witness s⃗^(1) ∈ R_q^{2ι}
    final_witness: Vec<R>,
    /// LaBRADOR compression (optional)
    labrador_proof: Option<LabradorProof<R>>,
}

pub struct EvalRound<R: Ring> {
    /// π⃗_{eval,i} = s^(k-i) · σ^{-1}(a⃗_0) · ∏_{j=1}^{k-i-2} a⃗_j ∈ R_q^2
    pub proof_vector: Vec<R>,
}

pub struct CommitmentRound<R: Ring> {
    /// π⃗_{cm,i} = G^{-1}_{2κ}(cm_{i,0}, cm_{i,1}) ∈ R_q^{2κι}
    pub decomposed_commitments: Vec<R>,
}

impl<R: Ring> HyperWolfProof<R> {
    /// Generate proof for k rounds
    pub fn generate(
        pp: &PublicParams<R>,
        witness: &[R],
        auxiliary_vectors: &[Vec<R>],  // (a⃗_i)_{i∈[0,k-1]}
        eval_value: &R::BaseField,
        norm_bound: &R::BaseField,
    ) -> Result<Self, Error> {
        let k = auxiliary_vectors.len();
        let mut current_witness = witness.to_vec();
        let mut eval_proofs = Vec::new();
        let mut norm_proofs = Vec::new();
        let mut commitment_proofs = Vec::new();
        
        // Reshape witness into k-dimensional tensor
        let mut tensor = WitnessTensor::from_vector(current_witness.clone(), k)?;
        
        for round in 0..k-1 {
            // Evaluation proof: compute π⃗_{eval,i}
            let eval_proof = self.compute_eval_round(
                &tensor,
                &auxiliary_vectors[0],
                &auxiliary_vectors[1..k-round-1],
            )?;
            
            // Norm proof: compute (L_i, M_i, R_i)
            let (left, right) = tensor.split();
            let norm_proof = self.compute_norm_round(&left, &right)?;
            
            // Commitment proof: compute π⃗_{cm,i}
            let commitment_proof = self.compute_commitment_round(
                &left,
                &right,
                pp,
            )?;
            
            eval_proofs.push(eval_proof);
            norm_proofs.push(norm_proof);
            commitment_proofs.push(commitment_proof);
            
            // Get challenge c⃗_{k-round-1} from Fiat-Shamir
            let challenge = self.get_challenge(round)?;
            
            // Fold witness: s⃗_{k-round-1} = c_{k-round-1,0} s⃗_L + c_{k-round-1,1} s⃗_R
            tensor = WitnessTensor::fold(&left, &right, &challenge)?;
        }
        
        // Final round: send s⃗^(1)
        let final_witness = tensor.to_vector();
        
        Ok(Self {
            eval_proofs,
            norm_proofs,
            commitment_proofs,
            final_witness,
            labrador_proof: None,
        })
    }
    
    /// Verify k-round proof
    pub fn verify(
        &self,
        pp: &PublicParams<R>,
        commitment: &Commitment<R>,
        auxiliary_vectors: &[Vec<R>],
        eval_value: &R::BaseField,
        norm_bound: &R::BaseField,
    ) -> Result<bool, Error> {
        let k = auxiliary_vectors.len();
        let mut challenges = Vec::new();
        
        // Round 0: Initial checks
        self.verify_round_0(
            &self.eval_proofs[0],
            &self.norm_proofs[0],
            &self.commitment_proofs[0],
            commitment,
            &auxiliary_vectors[k-1],
            eval_value,
            norm_bound,
        )?;
        
        challenges.push(self.get_challenge(0)?);
        
        // Rounds 1 to k-2: Recursive checks
        for round in 1..k-1 {
            self.verify_round_i(
                round,
                &self.eval_proofs[round],
                &self.norm_proofs[round],
                &self.commitment_proofs[round],
                &self.eval_proofs[round-1],
                &self.norm_proofs[round-1],
                &self.commitment_proofs[round-1],
                &auxiliary_vectors[k-round-1],
                &challenges[round-1],
                pp,
            )?;
            
            challenges.push(self.get_challenge(round)?);
        }
        
        // Final round: Check s⃗^(1)
        self.verify_final_round(
            &self.final_witness,
            &self.eval_proofs[k-2],
            &self.norm_proofs[k-2],
            &self.commitment_proofs[k-2],
            &auxiliary_vectors[0],
            &challenges[k-2],
            pp,
        )?;
        
        Ok(true)
    }
    
    /// Apply LaBRADOR compression
    pub fn compress_with_labrador(
        mut self,
        pp: &LabradorParams<R>,
    ) -> Result<Self, Error> {
        // Construct LaBRADOR input vectors (z⃗_0, ..., z⃗_{r-1})
        let r = 3 * self.eval_proofs.len() - 1;
        let n = r * r;
        let mut z_vectors = Vec::new();
        
        // Map HyperWolf proof components to LaBRADOR vectors
        for i in 0..self.eval_proofs.len() {
            z_vectors.push(self.eval_proofs[i].proof_vector.clone());
            z_vectors.push(vec![
                self.norm_proofs[i].L.clone(),
                self.norm_proofs[i].M.clone(),
                self.norm_proofs[i].R.clone(),
            ]);
            z_vectors.push(self.commitment_proofs[i].decomposed_commitments.clone());
        }
        z_vectors.push(self.final_witness.clone());
        z_vectors.push(conjugate_vector(&self.final_witness));
        
        // Pad vectors to length n
        for z in &mut z_vectors {
            z.resize(n, R::zero());
        }
        
        // Construct LaBRADOR function g and constraint vectors φ_i
        let (g_function, phi_vectors, beta) = self.construct_labrador_relation()?;
        
        // Run LaBRADOR protocol
        let labrador_proof = LabradorProof::prove(
            pp,
            &z_vectors,
            &g_function,
            &phi_vectors,
            beta,
        )?;
        
        self.labrador_proof = Some(labrador_proof);
        Ok(self)
    }
}
```

### 3. Integration with Neo Pay-Per-Bit Commitments

```rust
/// Unified commitment interface supporting both HyperWolf and Neo
pub enum UnifiedCommitment<R: Ring> {
    HyperWolf(HyperWolfCommitment<R>),
    NeoPayPerBit(NeoCommitment<R>),
}

impl<R: Ring> UnifiedCommitment<R> {
    /// Commit using specified scheme
    pub fn commit(
        scheme: CommitmentScheme,
        polynomial: &Polynomial<R::BaseField>,
        params: &CommitmentParams<R>,
    ) -> Result<Self, Error>;
    
    /// Prove evaluation using appropriate protocol
    pub fn prove_eval(
        &self,
        polynomial: &Polynomial<R::BaseField>,
        eval_point: &EvalPoint<R::BaseField>,
        eval_value: &R::BaseField,
    ) -> Result<EvaluationProof<R>, Error>;
    
    /// Verify evaluation using appropriate protocol
    pub fn verify_eval(
        &self,
        eval_point: &EvalPoint<R::BaseField>,
        eval_value: &R::BaseField,
        proof: &EvaluationProof<R>,
    ) -> Result<bool, Error>;
}

/// Bridge between HyperWolf and Neo commitments
pub struct CommitmentBridge<R: Ring> {
    hyperwolf_params: HyperWolfParams<R>,
    neo_params: NeoParams<R>,
}

impl<R: Ring> CommitmentBridge<R> {
    /// Convert Neo commitment to HyperWolf format
    pub fn neo_to_hyperwolf(
        &self,
        neo_commitment: &NeoCommitment<R>,
    ) -> Result<HyperWolfCommitment<R>, Error>;
    
    /// Convert HyperWolf commitment to Neo format
    pub fn hyperwolf_to_neo(
        &self,
        hyperwolf_commitment: &HyperWolfCommitment<R>,
    ) -> Result<NeoCommitment<R>, Error>;
    
    /// Prove equivalence of commitments
    pub fn prove_equivalence(
        &self,
        neo_commitment: &NeoCommitment<R>,
        hyperwolf_commitment: &HyperWolfCommitment<R>,
        witness: &[R],
    ) -> Result<EquivalenceProof<R>, Error>;
}
```


### 4. Integration with Symphony High-Arity Folding

```rust
/// Symphony SNARK with HyperWolf PCS backend
pub struct SymphonyWithHyperWolf<F: Field, R: Ring> {
    /// HyperWolf PCS parameters
    hyperwolf_params: HyperWolfParams<R>,
    /// Symphony folding parameters (arity 2^κ)
    symphony_params: SymphonyParams<F>,
    /// CCS relation
    ccs_relation: CCSRelation<F>,
}

impl<F: Field, R: Ring> SymphonyWithHyperWolf<F, R> {
    /// Setup Symphony with HyperWolf backend
    pub fn setup(
        security_param: usize,
        ccs_relation: CCSRelation<F>,
        folding_arity: usize,  // 2^κ for Symphony
    ) -> Result<Self, Error>;
    
    /// Prove CCS satisfaction using Symphony folding + HyperWolf PCS
    /// 1. Fold CCS instances using Symphony high-arity folding
    /// 2. Commit to folded witness using HyperWolf
    /// 3. Prove evaluation constraints using HyperWolf k-round protocol
    pub fn prove(
        &self,
        witness: &Witness<F>,
        instance: &Instance<F>,
    ) -> Result<SymphonyProof<R>, Error> {
        // Step 1: Symphony folding
        let folded_instances = self.symphony_fold(witness, instance)?;
        
        // Step 2: Convert to polynomial and commit with HyperWolf
        let polynomial = self.witness_to_polynomial(witness)?;
        let (commitment, state) = HyperWolfPCS::commit(
            &self.hyperwolf_params,
            &polynomial,
        )?;
        
        // Step 3: Prove evaluation constraints
        let eval_proofs = self.prove_ccs_evaluations(
            &polynomial,
            &commitment,
            &state,
            &folded_instances,
        )?;
        
        Ok(SymphonyProof {
            folding_proof: folded_instances,
            commitment,
            eval_proofs,
        })
    }
    
    /// Verify Symphony proof with HyperWolf verification
    pub fn verify(
        &self,
        instance: &Instance<F>,
        proof: &SymphonyProof<R>,
    ) -> Result<bool, Error> {
        // Verify Symphony folding
        self.verify_symphony_folding(&proof.folding_proof, instance)?;
        
        // Verify HyperWolf evaluation proofs
        for eval_proof in &proof.eval_proofs {
            HyperWolfPCS::verify_eval(
                &self.hyperwolf_params,
                &proof.commitment,
                &eval_proof.point,
                &eval_proof.value,
                &eval_proof.proof,
            )?;
        }
        
        Ok(true)
    }
    
    /// Convert CCS witness to multilinear polynomial
    fn witness_to_polynomial(
        &self,
        witness: &Witness<F>,
    ) -> Result<Polynomial<F>, Error> {
        // CCS witness w⃗ ∈ F^n becomes multilinear polynomial
        // w(X_0, ..., X_{log n - 1}) with evaluations w⃗
        Polynomial::from_evaluations(witness.values())
    }
    
    /// Prove CCS evaluation constraints using HyperWolf
    fn prove_ccs_evaluations(
        &self,
        polynomial: &Polynomial<F>,
        commitment: &Commitment<R>,
        state: &CommitmentState,
        folded_instances: &[FoldedInstance<F>],
    ) -> Result<Vec<EvaluationProof<R>>, Error> {
        let mut proofs = Vec::new();
        
        for instance in folded_instances {
            // For each CCS constraint, prove polynomial evaluation
            let eval_point = instance.challenge_point();
            let eval_value = polynomial.evaluate(&eval_point);
            
            let proof = HyperWolfPCS::prove_eval(
                &self.hyperwolf_params,
                commitment,
                polynomial,
                &eval_point,
                &eval_value,
                state,
            )?;
            
            proofs.push(EvaluationProof {
                point: eval_point,
                value: eval_value,
                proof,
            });
        }
        
        Ok(proofs)
    }
}

/// Symphony proof with HyperWolf backend
pub struct SymphonyProof<R: Ring> {
    /// Symphony folding proof
    pub folding_proof: Vec<FoldedInstance<R::BaseField>>,
    /// HyperWolf commitment to witness
    pub commitment: Commitment<R>,
    /// HyperWolf evaluation proofs for CCS constraints
    pub eval_proofs: Vec<EvaluationProof<R>>,
}
```

### 5. Integration with LatticeFold+ Two-Layer Folding

```rust
/// LatticeFold+ with HyperWolf PCS
pub struct LatticeFoldPlusHyperWolf<F: Field, R: Ring> {
    /// HyperWolf parameters
    hyperwolf_params: HyperWolfParams<R>,
    /// LatticeFold+ parameters
    latticefold_params: LatticeFoldParams<F>,
}

impl<F: Field, R: Ring> LatticeFoldPlusHyperWolf<F, R> {
    /// Fold two CCS instances using LatticeFold+ scheme
    /// Then commit to folded witness using HyperWolf
    pub fn fold_and_commit(
        &self,
        instance1: &Instance<F>,
        witness1: &Witness<F>,
        instance2: &Instance<F>,
        witness2: &Witness<F>,
    ) -> Result<FoldedCommitment<R>, Error> {
        // Step 1: LatticeFold+ two-layer folding
        let (folded_instance, folded_witness) = self.latticefold_fold(
            instance1, witness1,
            instance2, witness2,
        )?;
        
        // Step 2: Commit to folded witness using HyperWolf
        let polynomial = Polynomial::from_witness(&folded_witness);
        let (commitment, state) = HyperWolfPCS::commit(
            &self.hyperwolf_params,
            &polynomial,
        )?;
        
        Ok(FoldedCommitment {
            instance: folded_instance,
            commitment,
            state,
        })
    }
    
    /// Prove folded instance satisfies CCS using HyperWolf
    pub fn prove_folded(
        &self,
        folded: &FoldedCommitment<R>,
        polynomial: &Polynomial<F>,
    ) -> Result<FoldedProof<R>, Error> {
        // Prove CCS constraints on folded instance
        let eval_proofs = self.prove_ccs_constraints(
            &folded.instance,
            polynomial,
            &folded.commitment,
            &folded.state,
        )?;
        
        Ok(FoldedProof {
            commitment: folded.commitment.clone(),
            eval_proofs,
        })
    }
    
    /// Verify folded proof
    pub fn verify_folded(
        &self,
        folded_instance: &Instance<F>,
        proof: &FoldedProof<R>,
    ) -> Result<bool, Error> {
        // Verify each evaluation proof
        for eval_proof in &proof.eval_proofs {
            HyperWolfPCS::verify_eval(
                &self.hyperwolf_params,
                &proof.commitment,
                &eval_proof.point,
                &eval_proof.value,
                &eval_proof.proof,
            )?;
        }
        
        Ok(true)
    }
}

/// Combined folding and commitment
pub struct FoldedCommitment<R: Ring> {
    pub instance: Instance<R::BaseField>,
    pub commitment: Commitment<R>,
    pub state: CommitmentState,
}

pub struct FoldedProof<R: Ring> {
    pub commitment: Commitment<R>,
    pub eval_proofs: Vec<EvaluationProof<R>>,
}
```

### 6. Batching Support

```rust
/// Batching coordinator for multiple evaluation proofs
pub struct BatchingCoordinator<R: Ring> {
    hyperwolf_params: HyperWolfParams<R>,
}

impl<R: Ring> BatchingCoordinator<R> {
    /// Batch multiple polynomials at single point
    /// Uses random linear combination: f = Σ α_i f_i
    pub fn batch_multiple_polys_single_point(
        &self,
        claims: &[PolyEvalClaim<R>],
    ) -> Result<BatchedProof<R>, Error> {
        // Sample random challenge α⃗ ← Z_q^n
        let alphas = self.sample_random_challenges(claims.len())?;
        
        // Form linear combination f = Σ α_i f_i
        let combined_poly = self.combine_polynomials(claims, &alphas)?;
        
        // Compute combined value y = Σ α_i v_i
        let combined_value = self.combine_values(claims, &alphas)?;
        
        // Single HyperWolf proof for combined polynomial
        let proof = HyperWolfPCS::prove_eval(
            &self.hyperwolf_params,
            &combined_poly.commitment,
            &combined_poly.polynomial,
            &claims[0].eval_point,
            &combined_value,
            &combined_poly.state,
        )?;
        
        Ok(BatchedProof {
            alphas,
            combined_proof: proof,
        })
    }
    
    /// Batch single multilinear polynomial at multiple points
    /// Uses sum-check protocol reduction
    pub fn batch_single_poly_multiple_points(
        &self,
        polynomial: &Polynomial<R::BaseField>,
        commitment: &Commitment<R>,
        eval_points: &[Vec<R::BaseField>],
        eval_values: &[R::BaseField],
    ) -> Result<BatchedProof<R>, Error> {
        // Sample random challenge α⃗ ← Z_q^n
        let alphas = self.sample_random_challenges(eval_points.len())?;
        
        // Construct g(x⃗) = Σ α_i · f(x⃗) · eq̃(x⃗, u⃗_i)
        let g_polynomial = self.construct_sumcheck_polynomial(
            polynomial,
            eval_points,
            &alphas,
        )?;
        
        // Run sum-check protocol for Σ α_i v_i = Σ_{b⃗∈{0,1}^{log N}} g(b⃗)
        let sumcheck_proof = self.run_sumcheck(
            &g_polynomial,
            eval_values,
            &alphas,
        )?;
        
        // Reduce to single evaluation at random point r⃗
        let random_point = sumcheck_proof.random_point();
        let random_value = polynomial.evaluate(&random_point);
        
        // Single HyperWolf proof at random point
        let eval_proof = HyperWolfPCS::prove_eval(
            &self.hyperwolf_params,
            commitment,
            polynomial,
            &random_point,
            &random_value,
            &CommitmentState::default(),
        )?;
        
        Ok(BatchedProof {
            alphas,
            sumcheck_proof: Some(sumcheck_proof),
            combined_proof: eval_proof,
        })
    }
    
    /// Batch multiple polynomials at multiple points
    /// Combines both techniques
    pub fn batch_multiple_polys_multiple_points(
        &self,
        claims: &[MultiPointClaim<R>],
    ) -> Result<BatchedProof<R>, Error> {
        // Sample random challenge α⃗
        let alphas = self.sample_random_challenges(claims.len())?;
        
        // Construct combined polynomial g(x⃗) = Σ α_i · f_i(x⃗) · eq̃(x⃗, u⃗_i)
        let g_polynomial = self.construct_multi_poly_sumcheck(claims, &alphas)?;
        
        // Run sum-check
        let sumcheck_proof = self.run_sumcheck_multi_poly(&g_polynomial, claims, &alphas)?;
        
        // Reduce to single-point batching at random point
        let random_point = sumcheck_proof.random_point();
        let single_point_claims = self.evaluate_at_random_point(claims, &random_point)?;
        
        // Batch single-point evaluations
        let single_point_proof = self.batch_multiple_polys_single_point(&single_point_claims)?;
        
        Ok(BatchedProof {
            alphas,
            sumcheck_proof: Some(sumcheck_proof),
            combined_proof: single_point_proof.combined_proof,
        })
    }
}

pub struct BatchedProof<R: Ring> {
    pub alphas: Vec<R::BaseField>,
    pub sumcheck_proof: Option<SumCheckProof<R>>,
    pub combined_proof: HyperWolfProof<R>,
}
```


## Data Models

### Core Data Structures

```rust
/// Public parameters for HyperWolf PCS
pub struct HyperWolfParams<R: Ring> {
    /// Security parameter λ = 128
    pub security_param: usize,
    /// Polynomial degree bound N
    pub degree_bound: usize,
    /// Ring dimension d = 64
    pub ring_dim: usize,
    /// Number of rounds k = log(N/d)
    pub num_rounds: usize,
    /// Matrix height κ = 18
    pub matrix_height: usize,
    /// Decomposition basis b ∈ {4, 16}
    pub decomposition_basis: usize,
    /// ι = ⌈log_b q⌉
    pub decomposition_length: usize,
    /// Prime modulus q ≈ 2^128
    pub modulus: R::BaseField,
    /// Matrices A_0, A_1, ..., A_{k-1}
    pub matrices: Vec<Matrix<R>>,
    /// Challenge space C
    pub challenge_space: ChallengeSpace<R>,
    /// Norm bounds
    pub infinity_bound: R::BaseField,  // β_2
    pub l2_bound_squared: R::BaseField,  // β_1^2
}

/// Challenge space C ⊂ R_q
pub struct ChallengeSpace<R: Ring> {
    /// Ring dimension d
    pub ring_dim: usize,
    /// Number of zero coefficients (24 for d=64)
    pub num_zeros: usize,
    /// Number of ±1 coefficients (32 for d=64)
    pub num_ones: usize,
    /// Number of ±2 coefficients (8 for d=64)
    pub num_twos: usize,
    /// ℓ_2 norm bound τ = 8
    pub l2_norm_bound: usize,
    /// Operator norm bound T = 10
    pub operator_norm_bound: usize,
}

impl<R: Ring> ChallengeSpace<R> {
    /// Sample challenge c ∈ C with reject sampling
    pub fn sample_challenge(&self) -> Result<R, Error> {
        loop {
            let candidate = self.sample_candidate()?;
            if self.check_operator_norm(&candidate) {
                return Ok(candidate);
            }
        }
    }
    
    /// Check if c_1 - c_2 is invertible for all distinct c_1, c_2 ∈ C
    pub fn check_invertibility(&self, c1: &R, c2: &R) -> bool {
        let diff = c1.sub(c2);
        diff.is_invertible()
    }
}

/// Commitment to polynomial
pub struct Commitment<R: Ring> {
    /// Commitment value cm = F_{k-1,0}(s⃗)
    pub value: Vec<R>,
    /// Level in hierarchy
    pub level: usize,
}

/// Commitment state (for prover)
pub struct CommitmentState {
    /// Witness vector s⃗ ∈ R_q^n
    pub witness: Vec<R>,
    /// Decomposed witness
    pub decomposed_witness: Vec<R>,
}

/// Evaluation point (univariate or multilinear)
pub enum EvalPoint<F: Field> {
    Univariate(F),
    Multilinear(Vec<F>),
}

impl<F: Field> EvalPoint<F> {
    /// Construct auxiliary vectors (a⃗_i)_{i∈[0,k-1]} for evaluation
    pub fn to_auxiliary_vectors(
        &self,
        ring_dim: usize,
        num_rounds: usize,
    ) -> Result<Vec<Vec<F>>, Error> {
        match self {
            EvalPoint::Univariate(u) => {
                // a⃗_i = (1, u^{2^i d}) for i ∈ [1, k-1]
                // a⃗_0 = (1, u, u^2, ..., u^{2d-1})
                self.univariate_auxiliary_vectors(*u, ring_dim, num_rounds)
            }
            EvalPoint::Multilinear(u_vec) => {
                // a⃗_i = (1, u_{log d + i}) for i ∈ [1, k-1]
                // a⃗_0 = ⊗_{j=0}^{log d} (1, u_j)
                self.multilinear_auxiliary_vectors(u_vec, ring_dim, num_rounds)
            }
        }
    }
}

/// Polynomial representation
pub enum Polynomial<F: Field> {
    /// Univariate: f(X) = Σ f_i X^i
    Univariate {
        coefficients: Vec<F>,
        degree: usize,
    },
    /// Multilinear: f(X_0, ..., X_{ℓ-1})
    Multilinear {
        evaluations: Vec<F>,  // Evaluations on Boolean hypercube
        num_vars: usize,
    },
}

impl<F: Field> Polynomial<F> {
    /// Evaluate polynomial at point
    pub fn evaluate(&self, point: &EvalPoint<F>) -> F;
    
    /// Convert to coefficient vector f⃗
    pub fn to_coefficient_vector(&self) -> Vec<F>;
    
    /// Apply integer-to-ring mapping MR
    pub fn to_ring_vector<R: Ring>(&self, ring_dim: usize) -> Vec<R>;
}
```

### Integration Data Structures

```rust
/// Unified witness representation
pub struct UnifiedWitness<F: Field> {
    /// Original witness values
    pub values: Vec<F>,
    /// Witness as polynomial
    pub polynomial: Polynomial<F>,
    /// Witness as ring vector (after MR and decomposition)
    pub ring_vector: Vec<R>,
}

/// CCS relation for Symphony/LatticeFold+ integration
pub struct CCSRelation<F: Field> {
    /// Number of constraints
    pub num_constraints: usize,
    /// Number of variables
    pub num_variables: usize,
    /// Constraint matrices
    pub matrices: Vec<Matrix<F>>,
    /// Constraint selectors
    pub selectors: Vec<Vec<F>>,
}

/// Folded instance (from Symphony or LatticeFold+)
pub struct FoldedInstance<F: Field> {
    /// Folded public input
    pub public_input: Vec<F>,
    /// Challenge point for evaluation
    pub challenge_point: Vec<F>,
    /// Expected evaluation value
    pub expected_value: F,
}

/// Complete proof combining folding + HyperWolf
pub struct IntegratedProof<R: Ring> {
    /// Folding proof (Symphony or LatticeFold+)
    pub folding_proof: FoldingProof<R::BaseField>,
    /// HyperWolf commitment
    pub commitment: Commitment<R>,
    /// HyperWolf evaluation proofs
    pub eval_proofs: Vec<HyperWolfProof<R>>,
    /// Optional LaBRADOR compression
    pub labrador_proof: Option<LabradorProof<R>>,
}
```

## Error Handling

```rust
/// Error types for HyperWolf implementation
#[derive(Debug, Clone)]
pub enum HyperWolfError {
    /// Parameter validation errors
    InvalidParameters {
        reason: String,
    },
    /// M-SIS hardness not satisfied
    InsecureParameters {
        required_norm_bound: usize,
        actual_norm_bound: usize,
    },
    /// Wrap-around condition violated
    WrapAroundViolation {
        gamma: String,
        threshold: String,
    },
    /// Challenge sampling failed
    ChallengeSamplingFailed {
        attempts: usize,
    },
    /// Invertibility check failed
    NonInvertibleChallenge {
        challenge1: String,
        challenge2: String,
    },
    /// Norm bound check failed
    NormBoundViolation {
        actual_norm: String,
        bound: String,
    },
    /// Commitment verification failed
    CommitmentVerificationFailed {
        round: usize,
        reason: String,
    },
    /// Evaluation verification failed
    EvaluationVerificationFailed {
        round: usize,
        reason: String,
    },
    /// LaBRADOR constraint violated
    LabradorConstraintViolation {
        constraint: String,
    },
    /// Tensor dimension mismatch
    TensorDimensionMismatch {
        expected: Vec<usize>,
        actual: Vec<usize>,
    },
    /// Ring operation error
    RingOperationError {
        operation: String,
        reason: String,
    },
    /// Integration error with other schemes
    IntegrationError {
        scheme: String,
        reason: String,
    },
}

impl std::error::Error for HyperWolfError {}

impl std::fmt::Display for HyperWolfError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HyperWolfError::InvalidParameters { reason } => {
                write!(f, "Invalid parameters: {}", reason)
            }
            HyperWolfError::InsecureParameters { required_norm_bound, actual_norm_bound } => {
                write!(f, "Insecure parameters: M-SIS requires norm bound {}, but got {}", 
                       required_norm_bound, actual_norm_bound)
            }
            HyperWolfError::WrapAroundViolation { gamma, threshold } => {
                write!(f, "Wrap-around condition violated: 2γ = {} ≥ q/√n = {}", 
                       gamma, threshold)
            }
            // ... other error cases
            _ => write!(f, "HyperWolf error: {:?}", self),
        }
    }
}
```


## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    /// Test parameter generation and validation
    #[test]
    fn test_parameter_generation() {
        let params = HyperWolfParams::new(128, 1 << 20, 64);
        assert!(params.is_ok());
        
        let params = params.unwrap();
        assert_eq!(params.security_param, 128);
        assert_eq!(params.ring_dim, 64);
        assert!(params.validate_msis_hardness());
        assert!(params.validate_wraparound_condition());
    }
    
    /// Test challenge space properties
    #[test]
    fn test_challenge_space() {
        let challenge_space = ChallengeSpace::new(64);
        
        // Test challenge sampling
        let c1 = challenge_space.sample_challenge().unwrap();
        let c2 = challenge_space.sample_challenge().unwrap();
        
        // Test invertibility
        assert!(challenge_space.check_invertibility(&c1, &c2));
        
        // Test norm bounds
        assert!(c1.l2_norm() <= 8);
        assert!(c1.operator_norm() <= 10);
    }
    
    /// Test tensor operations
    #[test]
    fn test_tensor_operations() {
        let witness = vec![/* ... */];
        let tensor = WitnessTensor::from_vector(witness, 3).unwrap();
        
        // Test tensor-vector product
        let a_vec = vec![/* ... */];
        let result = tensor.tensor_vector_product(&a_vec).unwrap();
        assert_eq!(result.arity, 2);
        
        // Test split and fold
        let (left, right) = tensor.split();
        let challenge = [/* ... */];
        let folded = WitnessTensor::fold(&left, &right, &challenge).unwrap();
        assert_eq!(folded.arity, tensor.arity);
    }
    
    /// Test guarded IPA
    #[test]
    fn test_guarded_ipa() {
        let witness = vec![/* ... */];
        let norm_squared = compute_norm_squared(&witness);
        let infinity_bound = compute_infinity_bound(&witness);
        
        let proof = GuardedIPA::prove(&witness, &norm_squared, &infinity_bound).unwrap();
        
        let challenges = vec![/* ... */];
        assert!(proof.verify(&norm_squared, &infinity_bound, &challenges).unwrap());
    }
    
    /// Test leveled commitment
    #[test]
    fn test_leveled_commitment() {
        let params = HyperWolfParams::new(128, 1 << 20, 64).unwrap();
        let witness = vec![/* ... */];
        
        let commitment = LeveledCommitment::compute(
            &witness,
            &params.matrices,
            params.num_rounds - 1,
            0,
        ).unwrap();
        
        assert_eq!(commitment.level, params.num_rounds - 1);
    }
    
    /// Test complete k-round protocol
    #[test]
    fn test_k_round_protocol() {
        let params = HyperWolfParams::new(128, 1 << 20, 64).unwrap();
        let polynomial = Polynomial::random_univariate(1 << 20);
        let eval_point = EvalPoint::Univariate(/* ... */);
        let eval_value = polynomial.evaluate(&eval_point);
        
        let (commitment, state) = HyperWolfPCS::commit(&params, &polynomial).unwrap();
        
        let proof = HyperWolfPCS::prove_eval(
            &params,
            &commitment,
            &polynomial,
            &eval_point,
            &eval_value,
            &state,
        ).unwrap();
        
        assert!(HyperWolfPCS::verify_eval(
            &params,
            &commitment,
            &eval_point,
            &eval_value,
            &proof,
        ).unwrap());
    }
}
```

### Integration Tests

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    
    /// Test HyperWolf with Neo pay-per-bit commitments
    #[test]
    fn test_neo_integration() {
        let hyperwolf_params = HyperWolfParams::new(128, 1 << 20, 64).unwrap();
        let neo_params = NeoParams::new(128).unwrap();
        
        let bridge = CommitmentBridge::new(hyperwolf_params, neo_params);
        
        // Create Neo commitment
        let witness = vec![/* ... */];
        let neo_commitment = NeoCommitment::commit(&witness).unwrap();
        
        // Convert to HyperWolf
        let hyperwolf_commitment = bridge.neo_to_hyperwolf(&neo_commitment).unwrap();
        
        // Prove equivalence
        let equiv_proof = bridge.prove_equivalence(
            &neo_commitment,
            &hyperwolf_commitment,
            &witness,
        ).unwrap();
        
        assert!(equiv_proof.verify().unwrap());
    }
    
    /// Test HyperWolf with Symphony high-arity folding
    #[test]
    fn test_symphony_integration() {
        let ccs_relation = CCSRelation::random(100, 1000);
        let symphony = SymphonyWithHyperWolf::setup(128, ccs_relation, 16).unwrap();
        
        let (witness, instance) = generate_satisfying_witness(&symphony.ccs_relation);
        
        let proof = symphony.prove(&witness, &instance).unwrap();
        assert!(symphony.verify(&instance, &proof).unwrap());
    }
    
    /// Test HyperWolf with LatticeFold+ two-layer folding
    #[test]
    fn test_latticefold_integration() {
        let latticefold = LatticeFoldPlusHyperWolf::new(128).unwrap();
        
        let (instance1, witness1) = generate_instance();
        let (instance2, witness2) = generate_instance();
        
        let folded = latticefold.fold_and_commit(
            &instance1, &witness1,
            &instance2, &witness2,
        ).unwrap();
        
        let polynomial = Polynomial::from_witness(&folded.instance);
        let proof = latticefold.prove_folded(&folded, &polynomial).unwrap();
        
        assert!(latticefold.verify_folded(&folded.instance, &proof).unwrap());
    }
    
    /// Test batching multiple polynomials at single point
    #[test]
    fn test_batching_multiple_polys() {
        let params = HyperWolfParams::new(128, 1 << 20, 64).unwrap();
        let coordinator = BatchingCoordinator::new(params);
        
        let claims = vec![
            PolyEvalClaim { /* ... */ },
            PolyEvalClaim { /* ... */ },
            PolyEvalClaim { /* ... */ },
        ];
        
        let batched_proof = coordinator.batch_multiple_polys_single_point(&claims).unwrap();
        assert!(batched_proof.verify(&claims).unwrap());
    }
    
    /// Test batching single polynomial at multiple points
    #[test]
    fn test_batching_multiple_points() {
        let params = HyperWolfParams::new(128, 1 << 20, 64).unwrap();
        let coordinator = BatchingCoordinator::new(params);
        
        let polynomial = Polynomial::random_multilinear(20);
        let (commitment, _) = HyperWolfPCS::commit(&params, &polynomial).unwrap();
        
        let eval_points = vec![/* ... */];
        let eval_values: Vec<_> = eval_points.iter()
            .map(|p| polynomial.evaluate(&EvalPoint::Multilinear(p.clone())))
            .collect();
        
        let batched_proof = coordinator.batch_single_poly_multiple_points(
            &polynomial,
            &commitment,
            &eval_points,
            &eval_values,
        ).unwrap();
        
        assert!(batched_proof.verify(&commitment, &eval_points, &eval_values).unwrap());
    }
    
    /// Test LaBRADOR compression
    #[test]
    fn test_labrador_compression() {
        let params = HyperWolfParams::new(128, 1 << 20, 64).unwrap();
        let labrador_params = LabradorParams::new(128).unwrap();
        
        let polynomial = Polynomial::random_univariate(1 << 20);
        let eval_point = EvalPoint::Univariate(/* ... */);
        let eval_value = polynomial.evaluate(&eval_point);
        
        let (commitment, state) = HyperWolfPCS::commit(&params, &polynomial).unwrap();
        
        let mut proof = HyperWolfPCS::prove_eval(
            &params,
            &commitment,
            &polynomial,
            &eval_point,
            &eval_value,
            &state,
        ).unwrap();
        
        // Without LaBRADOR
        let size_before = proof.size();
        
        // With LaBRADOR
        proof = proof.compress_with_labrador(&labrador_params).unwrap();
        let size_after = proof.size();
        
        assert!(size_after < size_before);
        assert!(HyperWolfPCS::verify_eval(
            &params,
            &commitment,
            &eval_point,
            &eval_value,
            &proof,
        ).unwrap());
    }
}
```

### Property-Based Tests

```rust
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    
    proptest! {
        /// Test completeness: honest prover always succeeds
        #[test]
        fn test_completeness(
            degree in 1usize..1000,
            coeffs in prop::collection::vec(any::<u64>(), 1..1000),
        ) {
            let params = HyperWolfParams::new(128, degree, 64).unwrap();
            let polynomial = Polynomial::Univariate {
                coefficients: coeffs.clone(),
                degree,
            };
            
            let eval_point = EvalPoint::Univariate(/* random */);
            let eval_value = polynomial.evaluate(&eval_point);
            
            let (commitment, state) = HyperWolfPCS::commit(&params, &polynomial).unwrap();
            let proof = HyperWolfPCS::prove_eval(
                &params,
                &commitment,
                &polynomial,
                &eval_point,
                &eval_value,
                &state,
            ).unwrap();
            
            prop_assert!(HyperWolfPCS::verify_eval(
                &params,
                &commitment,
                &eval_point,
                &eval_value,
                &proof,
            ).unwrap());
        }
        
        /// Test soundness: malicious prover fails with wrong value
        #[test]
        fn test_soundness(
            degree in 1usize..1000,
            coeffs in prop::collection::vec(any::<u64>(), 1..1000),
        ) {
            let params = HyperWolfParams::new(128, degree, 64).unwrap();
            let polynomial = Polynomial::Univariate {
                coefficients: coeffs.clone(),
                degree,
            };
            
            let eval_point = EvalPoint::Univariate(/* random */);
            let correct_value = polynomial.evaluate(&eval_point);
            let wrong_value = correct_value + 1;  // Malicious value
            
            let (commitment, state) = HyperWolfPCS::commit(&params, &polynomial).unwrap();
            
            // Try to prove wrong value
            let result = HyperWolfPCS::prove_eval(
                &params,
                &commitment,
                &polynomial,
                &eval_point,
                &wrong_value,
                &state,
            );
            
            // Should fail or produce invalid proof
            prop_assert!(result.is_err() || 
                !HyperWolfPCS::verify_eval(
                    &params,
                    &commitment,
                    &eval_point,
                    &wrong_value,
                    &result.unwrap(),
                ).unwrap());
        }
    }
}
```


```


## Design Decisions and Rationales

### 1. Modular Architecture

**Decision**: Implement HyperWolf as a separate module that integrates with existing commitment schemes rather than replacing them entirely.

**Rationale**:
- Allows gradual migration and A/B testing
- Enables users to choose commitment scheme based on use case
- Facilitates comparison between HyperWolf and existing schemes
- Reduces risk of breaking existing functionality

### 2. Unified Commitment Interface

**Decision**: Create a `UnifiedCommitment` enum that abstracts over different commitment schemes.

**Rationale**:
- Provides consistent API for upper layers (Symphony, LatticeFold+)
- Enables runtime selection of commitment scheme
- Simplifies testing and benchmarking
- Allows seamless integration with existing code

### 3. Tensor-Based Witness Representation

**Decision**: Implement k-dimensional tensor operations as first-class primitives.

**Rationale**:
- Directly matches HyperWolf's mathematical structure
- Enables efficient axis-wise folding
- Simplifies proof generation logic
- Provides clear abstraction for witness manipulation

### 4. Guarded IPA as Separate Component

**Decision**: Implement guarded IPA as standalone module rather than embedding in main protocol.

**Rationale**:
- Reusable for other protocols requiring exact ℓ₂-soundness
- Easier to test and verify correctness
- Clear separation of concerns
- Facilitates future optimizations

### 5. Optional LaBRADOR Compression

**Decision**: Make LaBRADOR compression optional via `compress_with_labrador()` method.

**Rationale**:
- Allows users to trade proof size for prover time
- Useful for scenarios where verification time is more critical than proof size
- Enables benchmarking with and without compression
- Provides flexibility for different deployment scenarios

### 6. Batching as Separate Coordinator

**Decision**: Implement batching logic in dedicated `BatchingCoordinator` rather than in main PCS interface.

**Rationale**:
- Keeps core PCS interface simple
- Allows specialized optimizations for batching
- Easier to extend with new batching strategies
- Clear separation between single and batched proofs

### 7. Integration via Bridges

**Decision**: Use bridge pattern for integrating with Neo and other schemes.

**Rationale**:
- Avoids tight coupling between schemes
- Enables bidirectional conversion
- Provides clear integration points
- Facilitates testing of interoperability

### 8. Parameter Validation at Setup

**Decision**: Validate all security parameters during setup phase.

**Rationale**:
- Fail fast if parameters are insecure
- Prevents runtime errors due to invalid parameters
- Provides clear error messages for parameter selection
- Ensures M-SIS hardness and wrap-around conditions

### 9. Fiat-Shamir via Existing Infrastructure

**Decision**: Reuse existing Fiat-Shamir transformation infrastructure rather than implementing new one.

**Rationale**:
- Consistency with existing codebase
- Avoids duplication of cryptographic primitives
- Leverages tested and audited code
- Simplifies integration

### 10. Ring Operations via Existing Primitives

**Decision**: Build on existing ring arithmetic rather than reimplementing.

**Rationale**:
- Reuses optimized NTT implementations
- Maintains consistency with other protocols
- Reduces code duplication
- Leverages existing optimizations (SIMD, etc.)

## Performance Considerations

### Asymptotic Complexity

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Setup | O(N) | Generate matrices A_i |
| Commit | O(N) | Leveled commitment computation |
| Prove (without LaBRADOR) | O(N) | k-round witness folding |
| Verify (without LaBRADOR) | O(log N) | k-round verification |
| Proof Size (without LaBRADOR) | O(log N) | k rounds × O(1) per round |
| Prove (with LaBRADOR) | O(N) | Dominated by witness folding |
| Verify (with LaBRADOR) | O(log N) | Sparse LaBRADOR verification |
| Proof Size (with LaBRADOR) | O(log log log N) | LaBRADOR compression |

### Concrete Performance Targets

Based on paper benchmarks (λ = 128, κ = 18, ι = 32):

| N | Proof Size | Prover Time | Verifier Time |
|---|-----------|-------------|---------------|
| 2²⁰ | ~43 KB | ~X ms | ~Y ms |
| 2²⁶ | ~46 KB | ~X ms | ~Y ms |
| 2²⁸ | ~52 KB | ~X ms | ~Y ms |
| 2³⁰ | ~53 KB | ~X ms | ~Y ms |

### Optimization Strategies

1. **NTT-based Polynomial Multiplication**
   - Use Number Theoretic Transform for O(n log n) multiplication
   - Leverage existing optimized NTT implementations
   - Apply SIMD instructions where available

2. **Parallel Tensor Operations**
   - Parallelize independent tensor slices
   - Use rayon for work-stealing parallelism
   - Exploit multi-core architectures

3. **Memory Layout Optimization**
   - Use row-major order for cache-friendly access
   - Minimize allocations in hot paths
   - Reuse buffers where possible

4. **Challenge Sampling Optimization**
   - Pre-compute challenge space properties
   - Use efficient rejection sampling
   - Cache invertibility checks

5. **LaBRADOR Sparsity Exploitation**
   - Skip zero elements in inner products
   - Use sparse matrix representations
   - Optimize for O(log N) non-zeros

## Security Considerations

### Threat Model

1. **Malicious Prover**
   - Attempts to prove false statements
   - Tries to forge commitments
   - Sends invalid proofs

2. **Parameter Manipulation**
   - Selects weak parameters
   - Violates M-SIS hardness
   - Causes wrap-around in norm computation

3. **Challenge Manipulation**
   - Tries to predict challenges
   - Exploits weak randomness
   - Breaks Fiat-Shamir transformation

### Security Guarantees

1. **Completeness**: Perfect (ϵ = 0)
   - Honest prover always succeeds
   - No false rejections

2. **Knowledge Soundness**: 2(k-1)/|C| + 6(k-2)d+6dι/q ≤ 2⁻λ
   - Extractor recovers valid witness
   - Exact ℓ₂-norm (no relaxation)
   - Standard M-SIS assumption

3. **Weak Binding**: Under M-SISκ,n,q,2β
   - Computationally infeasible to open to two different polynomials
   - Reduction to M-SIS problem

4. **Zero-Knowledge** (optional): Statistical
   - Simulator produces indistinguishable transcripts
   - Requires commitment to norm value b

### Parameter Selection Guidelines

1. **Security Parameter**: λ = 128
   - Provides 128-bit security
   - Standard for post-quantum cryptography

2. **Modulus**: q ≈ 2¹²⁸, q ≡ 5 mod 8
   - Ensures M-SIS hardness
   - Enables efficient inversion (Lemma 1)

3. **Ring Dimension**: d = 64
   - Power of 2 for efficient NTT
   - Balances security and performance

4. **Matrix Height**: κ = 18
   - Satisfies M-SIS hardness threshold
   - Keeps commitment size reasonable

5. **Challenge Space**: |C| ≈ 2¹²⁸·⁶
   - Ensures negligible soundness error
   - Maintains invertibility property

6. **Decomposition Basis**: b ∈ {4, 16}
   - b = 4: Smaller ι, larger proof
   - b = 16: Larger ι, smaller proof
   - Trade-off between proof size and computation

7. **Norm Bounds**:
   - β₂ = b/2 (infinity bound)
   - β₁² = β₂² · nd (ℓ₂ bound squared)
   - Ensures 2γ < q/√n (no wrap-around)

## Future Enhancements

### 1. Tower-by-Tower IPA Optimization

**Goal**: Reduce proof size from O(log N) to O(log log N) without LaBRADOR.

**Approach**:
- Implement exponent-tower reduction
- Each round reduces from 2^(2^i) to 2^(2^(i-1))
- Requires careful challenge distribution analysis

**Benefits**:
- Better asymptotic proof size
- Simpler than LaBRADOR
- Potentially faster verification

### 2. Recursive Composition

**Goal**: Enable HyperWolf proofs to verify other HyperWolf proofs.

**Approach**:
- Express verification as polynomial constraints
- Use HyperWolf to prove verification circuit
- Build IVC (Incrementally Verifiable Computation)

**Benefits**:
- Enables proof aggregation
- Supports recursive SNARKs
- Useful for blockchain applications

### 3. Hardware Acceleration

**Goal**: Leverage specialized hardware for faster proving.

**Approach**:
- GPU acceleration for tensor operations
- FPGA implementation for NTT
- Custom ASIC for high-throughput proving

**Benefits**:
- Orders of magnitude speedup
- Lower energy consumption
- Enables real-time proving

### 4. Adaptive Parameter Selection

**Goal**: Automatically select optimal parameters based on use case.

**Approach**:
- Profile different parameter combinations
- Build cost model for proof size vs. time
- Provide parameter selection wizard

**Benefits**:
- Easier for users to deploy
- Optimal performance for each scenario
- Reduces parameter selection errors

### 5. Multi-Prover Support

**Goal**: Distribute proving across multiple machines.

**Approach**:
- Partition witness into independent chunks
- Prove each chunk in parallel
- Aggregate proofs efficiently

**Benefits**:
- Horizontal scalability
- Faster proving for large witnesses
- Better resource utilization

## Migration Path

### Phase 1: Core Implementation (Weeks 1-4)
1. Implement tensor operations
2. Implement guarded IPA
3. Implement leveled commitments
4. Implement k-round protocol
5. Basic unit tests

### Phase 2: Integration (Weeks 5-8)
1. Integrate with existing ring operations
2. Implement commitment bridge
3. Integrate with Fiat-Shamir
4. Integration tests with Neo
5. Integration tests with Symphony

### Phase 3: Optimization (Weeks 9-12)
1. Implement LaBRADOR compression
2. Implement batching coordinator
3. Optimize tensor operations
4. Optimize challenge sampling
5. Performance benchmarks

### Phase 4: Production Readiness (Weeks 13-16)
1. Comprehensive testing
2. Security audit
3. Documentation
4. Example applications
5. Deployment guide

## Conclusion

This design provides a comprehensive integration of HyperWolf PCS with the existing Neo-LatticeFold+ zkVM and Symphony SNARK framework. The modular architecture enables gradual adoption while maintaining compatibility with existing code. The design prioritizes:

1. **Correctness**: Exact ℓ₂-soundness under standard assumptions
2. **Efficiency**: O(log N) verification, O(log log log N) proof size
3. **Flexibility**: Support for univariate and multilinear polynomials
4. **Interoperability**: Clean integration with Neo, Symphony, and LatticeFold+
5. **Maintainability**: Clear interfaces and separation of concerns

The implementation will provide a state-of-the-art polynomial commitment scheme that advances the capabilities of lattice-based zkSNARKs while maintaining the security guarantees required for production deployment.
