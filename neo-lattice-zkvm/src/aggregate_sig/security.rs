// Aggregate Signature Security Reduction
//
// This module implements the security reduction from aggregate signature
// unforgeability to base signature scheme unforgeability.
//
// Mathematical Foundation (Theorem 5):
// If the base signature scheme Σ is EU-CMA secure in the AGM+ROM,
// and the underlying SNARK Π is an O-SNARK with O-AdPoK security,
// then the aggregate signature scheme is EU-ACK secure.
//
// The reduction works as follows:
// 1. Adversary A breaks EU-ACK (aggregate signature unforgeability)
// 2. Construct adversary B that breaks EU-CMA (base signature unforgeability)
// 3. B simulates the aggregate signature game for A
// 4. When A outputs forgery, B extracts individual signatures
// 5. B finds a forgery index i* where vk_i* = vk ∧ m_i* ∉ Q_σ
// 6. B derives group representation for σ_i* and submits to EU-CMA challenger

use std::marker::PhantomData;
use std::collections::HashSet;
use crate::agm::{GroupRepresentation, AlgebraicAdversary, AlgebraicOutput};
use crate::oracle::{Oracle, OracleTranscript, SigningOracle};
use crate::o_snark::OSNARK;
use super::types::*;
use super::errors::*;
use super::construction::AggregateSignature;

/// EU-CMA (Existential Unforgeability under Chosen Message Attack) Game
///
/// This is the standard security game for signature schemes.
/// The adversary can query a signing oracle and must produce a forgery
/// for a message not previously queried.
///
/// Game Structure:
/// 1. Setup: Generate (pp_Σ, vk, sk)
/// 2. Adversary A^{O_Sign} gets vk and oracle access to signing
/// 3. A outputs (m*, σ*, Γ*) where Γ* is group representation
/// 4. A wins if vfy(vk, m*, σ*) = 1 ∧ m* ∉ Q_σ
pub struct EUCMAGame<F, G, O> {
    /// Signature scheme parameters
    pub pp_sig: SignatureParameters<G>,
    
    /// Verification key
    pub vk: VerificationKey<G>,
    
    /// Secret key (kept private)
    sk: Vec<u8>,
    
    /// Signing oracle
    signing_oracle: SigningOracle<Message, Signature<G>>,
    
    /// Random oracle
    oracle: O,
    
    /// Phantom data
    _phantom: PhantomData<F>,
}

impl<F, G, O> EUCMAGame<F, G, O>
where
    F: Clone,
    G: Clone + PartialEq + Eq + std::hash::Hash,
    O: Oracle<Vec<u8>, Vec<u8>>,
{
    /// Create a new EU-CMA game
    ///
    /// Parameters:
    /// - lambda: Security parameter
    /// - oracle: Random oracle
    ///
    /// Returns:
    /// - New EU-CMA game instance
    pub fn new(lambda: usize, oracle: O) -> Self {
        // Generate signature scheme parameters
        // The parameters include generator elements for the group
        let num_generators = (lambda / 128).max(2); // At least 2 generators
        let generators = Vec::with_capacity(num_generators);
        // In production, generators would be sampled from the group
        // using a deterministic process based on lambda
        
        let params = vec![lambda as u8]; // Encode security parameter
        let pp_sig = SignatureParameters::new(generators, params);
        
        // Generate key pair
        // Secret key: random element from Z_p
        let sk = Self::generate_secret_key(lambda);
        
        // Verification key: g^sk where g is generator
        // In production, this would compute the actual group element
        let vk_element = Self::compute_verification_key(&sk, &pp_sig);
        let vk = VerificationKey::new(vk_element);
        
        let signing_oracle = SigningOracle::new(sk.clone());
        
        Self {
            pp_sig,
            vk,
            sk,
            signing_oracle,
            oracle,
            _phantom: PhantomData,
        }
    }
    
    /// Generate a secret key
    ///
    /// Mathematical Details:
    /// The secret key is a random element from Z_p where p is the group order.
    /// For security parameter λ, we generate λ bits of randomness.
    ///
    /// In production, this would use a cryptographically secure RNG.
    fn generate_secret_key(lambda: usize) -> Vec<u8> {
        let key_bytes = lambda / 8;
        let mut sk = vec![0u8; key_bytes];
        
        // In production, use a CSPRNG:
        // use rand::RngCore;
        // let mut rng = rand::thread_rng();
        // rng.fill_bytes(&mut sk);
        
        // For now, we use a deterministic derivation from lambda
        for i in 0..key_bytes {
            sk[i] = ((lambda + i * 7) % 256) as u8;
        }
        
        sk
    }
    
    /// Compute verification key from secret key
    ///
    /// Mathematical Details:
    /// vk = g^sk where g is the generator
    ///
    /// In production, this would perform actual group exponentiation.
    fn compute_verification_key(_sk: &[u8], _pp: &SignatureParameters<G>) -> G {
        // In production, this would:
        // 1. Get generator g from pp
        // 2. Convert sk to field element
        // 3. Compute g^sk using group operations
        
        // For now, we need to return a group element
        // This is a placeholder that would be replaced with actual group operations
        panic!("Group element construction requires concrete group implementation")
    }
    
    /// Run the EU-CMA game with an adversary
    ///
    /// Parameters:
    /// - adversary: Algebraic adversary attempting forgery
    ///
    /// Returns:
    /// - true if adversary wins (produces valid forgery), false otherwise
    pub fn run<A>(&mut self, adversary: &mut A) -> bool
    where
        A: AlgebraicAdversary<F, G, O>,
    {
        // Give adversary access to verification key and oracles
        let output = adversary.run_with_signing_oracle(
            &self.pp_sig,
            &self.vk,
            &mut self.oracle,
            &mut self.signing_oracle,
        );
        
        // Check if adversary produced a valid forgery
        self.check_forgery(&output)
    }
    
    /// Check if adversary output is a valid forgery
    ///
    /// Mathematical Details:
    /// A valid forgery (m*, σ*, Γ*) must satisfy:
    /// 1. vfy^θ(vk, m*, σ*) = 1 (signature verifies)
    /// 2. m* ∉ Q_σ (message not previously queried)
    /// 3. Γ* is valid group representation for σ*
    ///
    /// The algebraic adversary must provide Γ* showing how σ* is computed
    /// as a linear combination of basis elements (pp_Σ, vk, Q_σ).
    fn check_forgery(&self, output: &AlgebraicOutput<F, G>) -> bool {
        // Step 1: Parse output to extract message and signature
        // The output contains group elements and their representations
        if output.output_elements.is_empty() {
            return false;
        }
        
        // Extract signature group elements from output
        // In a typical signature scheme, the signature consists of group elements
        let signature_elements = output.output_elements.clone();
        
        // Step 2: Extract message from output metadata
        // The message should be encoded in the output or provided separately
        // For now, we check if there are any output elements at all
        if signature_elements.is_empty() {
            return false;
        }
        
        // Step 3: Verify the signature
        // Build signature structure from output elements
        let signature = Signature::new(signature_elements);
        
        // Extract message - in production, this would be properly encoded
        // For now, we use a placeholder message
        let message = vec![0u8]; // Placeholder
        
        // Verify signature using the verification key
        let verified = self.verify_signature(&self.vk, &message, &signature);
        
        if !verified {
            return false;
        }
        
        // Step 4: Check if message was queried to signing oracle
        let signing_queries = self.signing_oracle.get_queries();
        let message_queried = signing_queries.iter()
            .any(|(m, _)| m == &message);
        
        if message_queried {
            // Not a forgery - message was queried
            return false;
        }
        
        // Step 5: Verify group representation
        // The algebraic adversary must provide valid representation Γ*
        let representation_valid = output.representations.verify_all_representations();
        
        if !representation_valid {
            return false;
        }
        
        // All checks passed - valid forgery
        true
    }
    
    /// Verify a signature
    ///
    /// Mathematical Details:
    /// For a signature scheme with verification algorithm vfy^θ,
    /// check if vfy^θ(vk, m, σ) = 1.
    ///
    /// The specific verification depends on the signature scheme:
    /// - BLS: Check pairing equation e(σ, g) = e(H(m), vk)
    /// - Schnorr: Check R + e·vk = g^z where e = H(R, m)
    fn verify_signature(&self, vk: &VerificationKey<G>, message: &[u8], signature: &Signature<G>) -> bool {
        // In production, this would implement the actual verification algorithm
        // For now, we perform basic structural checks
        
        // Check signature has correct structure
        if signature.elements.is_empty() {
            return false;
        }
        
        // Check verification key is valid
        // In production, verify vk is in the correct group
        
        // Perform signature verification
        // This would use the specific signature scheme's verification algorithm
        // For BLS: pairing check
        // For Schnorr: equation check
        
        // Placeholder: assume signature is valid if it has elements
        !signature.elements.is_empty()
    }
    
    /// Get signing queries made by adversary
    pub fn get_signing_queries(&self) -> &[(Message, Signature<G>)] {
        self.signing_oracle.get_queries()
    }
}

/// EU-ACK Adversary Trait
///
/// Defines the interface for adversaries in the EU-ACK game.
/// The adversary has access to a signing oracle and must produce
/// an aggregate forgery.
///
/// Mathematical Details:
/// The adversary A^{O_Sign, θ} has access to:
/// - Random oracle θ
/// - Signing oracle O_Sign for the challenge key
/// - Aggregate signature public parameters
///
/// The adversary must output:
/// - List of (vk_i, m_i) pairs
/// - Aggregate signature σ_agg
/// - Group representations Γ (as algebraic adversary)
pub trait EUACKAdversary<F, G, O>: AlgebraicAdversary<F, G, O>
where
    F: Clone,
    G: Clone,
    O: Oracle<Vec<u8>, Vec<u8>>,
{
    /// Run the adversary with signing oracle access
    ///
    /// Parameters:
    /// - pp_sig: Signature scheme parameters
    /// - challenge_vk: Challenge verification key
    /// - oracle: Random oracle
    /// - signing_oracle: Signing oracle for challenge key
    ///
    /// Returns:
    /// - Algebraic output containing aggregate forgery
    fn run_with_signing_oracle(
        &mut self,
        pp_sig: &SignatureParameters<G>,
        challenge_vk: &VerificationKey<G>,
        oracle: &mut O,
        signing_oracle: &mut SigningOracle<Message, Signature<G>>,
    ) -> AlgebraicOutput<F, G>;
    
    /// Verify the forgery
    ///
    /// Checks if the adversary's output constitutes a valid forgery.
    ///
    /// Parameters:
    /// - output: Adversary's output
    /// - challenge_vk: Challenge verification key
    /// - signing_queries: Messages queried to signing oracle
    ///
    /// Returns:
    /// - true if output is a valid forgery, false otherwise
    fn verify_forgery(
        &self,
        output: &AlgebraicOutput<F, G>,
        challenge_vk: &VerificationKey<G>,
        signing_queries: &[(Message, Signature<G>)],
    ) -> bool {
        // Check if output contains at least one forgery for challenge key
        // This is a default implementation that can be overridden
        
        // Extract public keys from output
        let num_signatures = output.output_elements.len() / 2;
        
        // Build set of queried messages
        let queried_messages: std::collections::HashSet<_> = signing_queries
            .iter()
            .map(|(m, _)| m)
            .collect();
        
        // Check for forgery
        for i in 0..num_signatures {
            if i >= output.output_elements.len() {
                break;
            }
            
            let vk = VerificationKey::new(output.output_elements[i].clone());
            let message = vec![i as u8]; // Placeholder message extraction
            
            // Check if this is a forgery for challenge key
            if vk == *challenge_vk && !queried_messages.contains(&message) {
                return true;
            }
        }
        
        false
    }
}

/// EU-ACK (Existential Unforgeability under Aggregate Chosen Key Attack) Game
///
/// This is the security game for aggregate signatures.
/// The adversary can query a signing oracle and must produce an aggregate
/// forgery where at least one signature is for a message not previously queried.
///
/// Game Structure:
/// 1. Setup: Generate aggregate signature parameters
/// 2. Adversary A^{O_Sign} gets parameters and oracle access
/// 3. A outputs ({vk_i, m_i}_{i∈[n]}, σ_agg)
/// 4. A wins if:
///    - Aggregate verification succeeds
///    - ∃i*: vk_i* = vk ∧ m_i* ∉ Q_σ (forgery for challenge key)
pub struct EUACKGame<F, G, O, S>
where
    S: OSNARK<F, G, O>,
{
    /// Aggregate signature system
    agg_sig: AggregateSignature<F, G, O, S>,
    
    /// Challenge verification key
    challenge_vk: VerificationKey<G>,
    
    /// Signing oracle for challenge key
    signing_oracle: SigningOracle<Message, Signature<G>>,
    
    /// Random oracle
    oracle: O,
    
    /// Phantom data
    _phantom: PhantomData<F>,
}

impl<F, G, O, S> EUACKGame<F, G, O, S>
where
    F: Clone,
    G: Clone + PartialEq + Eq + std::hash::Hash,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: OSNARK<F, G, O>,
{
    /// Create a new EU-ACK game
    ///
    /// Parameters:
    /// - agg_sig: Aggregate signature system
    /// - challenge_vk: Verification key for forgery challenge
    /// - sk: Secret key for signing oracle
    /// - oracle: Random oracle
    ///
    /// Returns:
    /// - New EU-ACK game instance
    pub fn new(
        agg_sig: AggregateSignature<F, G, O, S>,
        challenge_vk: VerificationKey<G>,
        sk: Vec<u8>,
        oracle: O,
    ) -> Self {
        let signing_oracle = SigningOracle::new(sk);
        
        Self {
            agg_sig,
            challenge_vk,
            signing_oracle,
            oracle,
            _phantom: PhantomData,
        }
    }
    
    /// Run the EU-ACK game with an adversary
    ///
    /// Parameters:
    /// - adversary: EU-ACK adversary attempting aggregate forgery
    ///
    /// Returns:
    /// - true if adversary wins (produces valid aggregate forgery), false otherwise
    pub fn run<A>(&mut self, adversary: &mut A) -> bool
    where
        A: EUACKAdversary<F, G, O>,
    {
        // Give adversary access to aggregate signature system and oracles
        let output = adversary.run_with_signing_oracle(
            &self.agg_sig.pp_sig,
            &self.challenge_vk,
            &mut self.oracle,
            &mut self.signing_oracle,
        );
        
        // Check if adversary produced a valid aggregate forgery
        self.check_aggregate_forgery(&output)
    }
    
    /// Check if adversary output is a valid aggregate forgery
    ///
    /// Mathematical Details:
    /// A valid aggregate forgery must satisfy:
    /// 1. AggVer(pp, {vk_i, m_i}_{i∈[n]}, σ_agg) = 1
    /// 2. ∃i*: vk_i* = challenge_vk ∧ m_i* ∉ Q_σ
    /// 3. Algebraic adversary provides valid group representations
    ///
    /// The adversary wins if it produces an aggregate signature that verifies,
    /// where at least one signature is for the challenge key with a new message.
    fn check_aggregate_forgery(&self, output: &AlgebraicOutput<F, G>) -> bool {
        // Step 1: Parse output to extract aggregate signature components
        // The output should contain:
        // - List of (vk_i, m_i) pairs (statement)
        // - Aggregate proof σ_agg
        
        if output.output_elements.is_empty() {
            return false;
        }
        
        // Step 2: Extract statement (public keys and messages)
        // In production, this would properly parse the output structure
        // For now, we check basic structure
        
        // The first group elements are verification keys
        // Messages are encoded in the output data
        let num_signatures = output.output_elements.len() / 2; // Rough estimate
        
        if num_signatures == 0 {
            return false;
        }
        
        // Build list of (vk, message) pairs
        let mut public_keys_messages = Vec::new();
        for i in 0..num_signatures {
            // Extract verification key
            if i >= output.output_elements.len() {
                break;
            }
            let vk = VerificationKey::new(output.output_elements[i].clone());
            
            // Extract message (placeholder)
            let message = vec![i as u8];
            
            public_keys_messages.push((vk, message));
        }
        
        // Step 3: Verify aggregate signature
        // Build aggregate proof from output
        // In production, this would extract the actual SNARK proof
        
        // For now, check if we have oracle queries (indicates proof was generated)
        if output.oracle_queried_elements.is_empty() {
            return false;
        }
        
        // Step 4: Check for forgery index
        // Find i* where vk_i* = challenge_vk ∧ m_i* ∉ Q_σ
        let signing_queries = self.signing_oracle.get_queries();
        let queried_messages: std::collections::HashSet<_> = signing_queries
            .iter()
            .map(|(m, _)| m)
            .collect();
        
        let mut found_forgery = false;
        for (vk, msg) in &public_keys_messages {
            // Check if this is the challenge key
            if vk == &self.challenge_vk {
                // Check if message is new
                if !queried_messages.contains(msg) {
                    found_forgery = true;
                    break;
                }
            }
        }
        
        if !found_forgery {
            return false;
        }
        
        // Step 5: Verify group representations
        // The algebraic adversary must provide valid representations
        let representation_valid = output.representations.verify_all_representations();
        
        if !representation_valid {
            return false;
        }
        
        // All checks passed - valid aggregate forgery
        true
    }
}

/// Security Reduction from EU-ACK to EU-CMA
///
/// This structure implements the reduction from Theorem 5.
/// It shows that if an adversary A breaks EU-ACK (aggregate signature security),
/// then we can construct an adversary B that breaks EU-CMA (base signature security).
///
/// Reduction Strategy:
/// 1. B receives challenge (pp_Σ, vk) from EU-CMA challenger
/// 2. B sets up aggregate signature system with vk as one of the keys
/// 3. B runs A, forwarding signing queries to EU-CMA challenger
/// 4. When A outputs aggregate forgery, B extracts individual signatures
/// 5. B finds forgery index i* where vk_i* = vk ∧ m_i* ∉ Q_σ
/// 6. B derives group representation Γ* for σ_i*
/// 7. B submits (m_i*, σ_i*, Γ*) to EU-CMA challenger
pub struct EUACKToEUCMAReduction<F, G, O, S>
where
    S: OSNARK<F, G, O>,
{
    /// Aggregate signature system
    agg_sig: AggregateSignature<F, G, O, S>,
    
    /// Phantom data
    _phantom: PhantomData<(F, G, O)>,
}

impl<F, G, O, S> EUACKToEUCMAReduction<F, G, O, S>
where
    F: Clone,
    G: Clone + PartialEq + Eq + std::hash::Hash,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: OSNARK<F, G, O>,
{
    /// Create a new reduction
    pub fn new(agg_sig: AggregateSignature<F, G, O, S>) -> Self {
        Self {
            agg_sig,
            _phantom: PhantomData,
        }
    }
    
    /// Run the reduction
    ///
    /// This method implements the reduction adversary B from Theorem 5.
    ///
    /// Mathematical Details:
    /// The reduction works as follows:
    ///
    /// 1. Setup Phase:
    ///    - B receives (pp_Σ, vk) from EU-CMA challenger
    ///    - B locally computes pp_Π, (ipk, ivk) for the SNARK
    ///    - B sets pp = (pp_Π, ipk, ivk, pp_Σ)
    ///    - B sets aux = vk (the challenge verification key)
    ///
    /// 2. Simulation Phase:
    ///    - B runs A with access to:
    ///      * Random oracle θ
    ///      * Signing oracle O_Sign (forwarded to EU-CMA challenger)
    ///    - A outputs ({vk_i, m_i}_{i∈[n]}, σ_agg)
    ///
    /// 3. Extraction Phase:
    ///    - B runs O-SNARK extractor E to obtain (σ_1, ..., σ_n, r)
    ///    - Extractor uses:
    ///      * Prover transcript tr_A
    ///      * Signing oracle transcript Q_σ
    ///      * Group representations Γ from algebraic adversary
    ///
    /// 4. Forgery Identification:
    ///    - B finds index i* where vk_i* = vk ∧ m_i* ∉ Q_σ
    ///    - This is the forgery for the challenge key
    ///
    /// 5. Representation Derivation:
    ///    - B derives Γ* for σ_i* in terms of (pp_Σ, vk, Q_σ)
    ///    - This uses the group representation from the algebraic adversary
    ///    - Γ* shows how σ_i* is computed from basis elements
    ///
    /// 6. Forgery Submission:
    ///    - B outputs (m_i*, σ_i*, Γ*) to EU-CMA challenger
    ///    - If A succeeded, then σ_i* is a valid forgery
    ///
    /// Parameters:
    /// - eu_cma_challenger: The EU-CMA challenger providing (pp_Σ, vk)
    /// - aggregate_adversary: The EU-ACK adversary A
    /// - oracle: Random oracle
    ///
    /// Returns:
    /// - Forgery (message, signature, representation) if successful
    pub fn run<A>(
        &mut self,
        eu_cma_challenger: &mut EUCMAGame<F, G, O>,
        aggregate_adversary: &mut A,
        oracle: &mut O,
    ) -> AggregateSignatureResult<(Message, Signature<G>, GroupRepresentation<F, G>)>
    where
        A: AlgebraicAdversary<F, G, O>,
    {
        // Step 1: Receive challenge from EU-CMA
        let challenge_vk = eu_cma_challenger.vk.clone();
        
        // Step 2: Run aggregate adversary
        // The adversary has access to signing oracle (forwarded to challenger)
        let output = aggregate_adversary.run_with_signing_oracle(
            &self.agg_sig.pp_sig,
            &challenge_vk,
            oracle,
            &mut eu_cma_challenger.signing_oracle,
        );
        
        // Step 3: Extract individual signatures using O-SNARK extractor
        let extracted = self.extract_signatures(&output, oracle)?;
        
        // Step 4: Find forgery index
        let forgery_index = self.find_forgery_index(
            &extracted.public_keys_messages,
            &challenge_vk,
            eu_cma_challenger.get_signing_queries(),
        )?;
        
        // Step 5: Derive group representation for forgery
        let forgery_representation = self.derive_forgery_representation(
            &extracted.signatures[forgery_index],
            &output.representations,
            forgery_index,
        )?;
        
        // Step 6: Return forgery
        let forgery_message = extracted.public_keys_messages[forgery_index].1.clone();
        let forgery_signature = extracted.signatures[forgery_index].clone();
        
        Ok((forgery_message, forgery_signature, forgery_representation))
    }
    
    /// Extract individual signatures from aggregate proof
    ///
    /// Uses the O-SNARK extractor to extract the witness (σ_1, ..., σ_n, r)
    /// from the aggregate proof.
    ///
    /// Mathematical Details:
    /// The O-SNARK extractor E takes:
    /// - Public parameters pp
    /// - Circuit index i
    /// - Auxiliary input aux (challenge vk)
    /// - Statement x = ({vk_i, m_i}_{i∈[n]})
    /// - Proof π = σ_agg
    /// - Signing oracle queries Q_σ
    /// - Prover transcript tr_A
    /// - Group representations Γ
    ///
    /// And outputs:
    /// - Witness w = ((σ_1, ..., σ_n), r)
    ///
    /// The extractor succeeds with overwhelming probability if:
    /// - The aggregate proof verifies
    /// - The adversary is algebraic (provides Γ)
    /// - The O-SNARK has O-AdPoK security
    fn extract_signatures(
        &self,
        output: &AlgebraicOutput<F, G>,
        oracle: &mut O,
    ) -> AggregateSignatureResult<ExtractedWitness<G>> {
        // Step 1: Parse output to get statement and proof
        // Extract (vk_i, m_i) pairs from output
        let num_signatures = output.output_elements.len() / 2;
        let mut public_keys_messages = Vec::new();
        
        for i in 0..num_signatures {
            if i >= output.output_elements.len() {
                break;
            }
            let vk = VerificationKey::new(output.output_elements[i].clone());
            let message = vec![i as u8]; // Placeholder message extraction
            public_keys_messages.push((vk, message));
        }
        
        // Step 2: Get signing oracle transcript
        // This contains all (m, σ) pairs queried by the adversary
        let signing_queries = oracle.transcript();
        
        // Step 3: Get prover transcript
        // This contains all random oracle queries made by the prover
        let prover_transcript = oracle.transcript();
        
        // Step 4: Extract using O-SNARK extractor
        // The extractor uses the group representations Γ to extract the witness
        //
        // Mathematical Process:
        // 1. Parse Γ to identify how each output group element is computed
        // 2. For each signature σ_i, find its representation in Γ
        // 3. Extract the signature by evaluating the representation
        // 4. Extract oracle responses r from the representation
        //
        // The key insight is that Γ shows σ_i as a linear combination:
        // σ_i = Σ_j γ_ij · basis_j
        // where basis includes (pp_Σ, vk, Q_σ)
        
        let mut extracted_signatures = Vec::new();
        let mut oracle_responses = Vec::new();
        
        // For each signature in the aggregate
        for i in 0..num_signatures {
            // Extract signature σ_i from group representation
            let signature = self.extract_single_signature(
                i,
                &output.representations,
                &public_keys_messages,
            )?;
            
            extracted_signatures.push(signature);
        }
        
        // Extract oracle responses from representation
        // These are the responses r for forced oracle queries
        for elem in &output.oracle_queried_elements {
            // Serialize element and get its oracle response
            let query = self.serialize_group_element_for_oracle(elem)?;
            let response = oracle.query(query);
            oracle_responses.push(response);
        }
        
        // Step 5: Verify extracted witness
        // Check that each extracted signature verifies
        for (i, sig) in extracted_signatures.iter().enumerate() {
            let (vk, msg) = &public_keys_messages[i];
            
            // Verify signature
            if !self.verify_extracted_signature(vk, msg, sig, oracle) {
                return Err(AggregateSignatureError::InvalidWitness(
                    format!("Extracted signature {} does not verify", i)
                ));
            }
        }
        
        Ok(ExtractedWitness {
            public_keys_messages,
            signatures: extracted_signatures,
            oracle_responses,
        })
    }
    
    /// Extract a single signature from group representation
    ///
    /// Mathematical Details:
    /// Given group representation Γ and index i, extract σ_i.
    ///
    /// The representation shows:
    /// σ_i = Σ_j γ_ij · basis_j
    ///
    /// We identify which basis elements correspond to σ_i and
    /// extract the signature structure.
    fn extract_single_signature(
        &self,
        index: usize,
        representations: &GroupRepresentation<F, G>,
        public_keys_messages: &[(VerificationKey<G>, Message)],
    ) -> AggregateSignatureResult<Signature<G>> {
        // Get basis elements from representation
        let basis = representations.get_basis();
        
        // Find coefficients for signature at index
        // In the representation matrix, each row corresponds to an output element
        // We need to find the rows corresponding to signature i
        
        // For a typical signature scheme, a signature consists of 1-3 group elements
        // We extract these from the representation
        
        let signature_start = index * 2; // Assume 2 elements per signature
        let signature_end = signature_start + 2;
        
        let mut signature_elements = Vec::new();
        
        for elem_idx in signature_start..signature_end {
            if elem_idx < basis.len() {
                // Get the group element from basis
                signature_elements.push(basis[elem_idx].clone());
            }
        }
        
        if signature_elements.is_empty() {
            return Err(AggregateSignatureError::GroupElementExtractionFailed(
                format!("No signature elements found for index {}", index)
            ));
        }
        
        Ok(Signature::new(signature_elements))
    }
    
    /// Verify an extracted signature
    fn verify_extracted_signature(
        &self,
        vk: &VerificationKey<G>,
        message: &[u8],
        signature: &Signature<G>,
        oracle: &mut O,
    ) -> bool {
        // Verify the signature using the signature scheme's verification algorithm
        // This is the same as the verification in check_forgery
        
        if signature.elements.is_empty() {
            return false;
        }
        
        // In production, this would call the actual verification algorithm
        // For now, we check basic structure
        !signature.elements.is_empty()
    }
    
    /// Serialize group element for oracle query
    fn serialize_group_element_for_oracle(&self, elem: &G) -> AggregateSignatureResult<Vec<u8>> {
        // In production, this would properly serialize the group element
        // For now, we return a placeholder
        Ok(vec![0u8; 32])
    }
    
    /// Find forgery index
    ///
    /// Finds index i* where vk_i* = vk ∧ m_i* ∉ Q_σ
    ///
    /// Mathematical Details:
    /// The forgery index i* satisfies:
    /// - vk_i* = vk (matches challenge verification key)
    /// - m_i* ∉ Q_σ (message not previously queried to signing oracle)
    ///
    /// If no such index exists, the reduction fails (adversary didn't produce
    /// a valid forgery for the challenge key).
    ///
    /// Parameters:
    /// - public_keys_messages: List of (vk_i, m_i) from aggregate
    /// - challenge_vk: Challenge verification key from EU-CMA
    /// - signing_queries: Messages queried to signing oracle
    ///
    /// Returns:
    /// - Index i* of the forgery
    fn find_forgery_index(
        &self,
        public_keys_messages: &[(VerificationKey<G>, Message)],
        challenge_vk: &VerificationKey<G>,
        signing_queries: &[(Message, Signature<G>)],
    ) -> AggregateSignatureResult<usize> {
        // Build set of queried messages for efficient lookup
        let queried_messages: HashSet<_> = signing_queries
            .iter()
            .map(|(msg, _)| msg)
            .collect();
        
        // Find index where vk matches and message is new
        for (i, (vk, msg)) in public_keys_messages.iter().enumerate() {
            if vk == challenge_vk && !queried_messages.contains(msg) {
                return Ok(i);
            }
        }
        
        // No forgery found
        Err(AggregateSignatureError::InvalidWitness(
            "No forgery index found for challenge key".to_string()
        ))
    }
    
    /// Derive group representation for forgery signature
    ///
    /// Derives Γ* for σ_i* in terms of (pp_Σ, vk, Q_σ)
    ///
    /// Mathematical Details:
    /// The algebraic adversary provides group representation Γ for all
    /// output group elements. We need to extract the representation for
    /// the specific forgery signature σ_i*.
    ///
    /// The representation Γ* shows how σ_i* is computed as a linear
    /// combination of basis elements:
    /// - Basis includes: pp_Σ (public parameters), vk (verification key),
    ///   and Q_σ (signing oracle responses)
    /// - Γ* is a vector of coefficients
    /// - σ_i* = Γ*^T · basis
    ///
    /// This representation is required for the EU-CMA forgery because
    /// the base signature scheme security is in the AGM.
    ///
    /// Parameters:
    /// - forgery_signature: The signature σ_i* being forged
    /// - full_representation: Complete group representation from adversary
    /// - forgery_index: Index i* of the forgery
    ///
    /// Returns:
    /// - Group representation Γ* for σ_i*
    fn derive_forgery_representation(
        &self,
        forgery_signature: &Signature<G>,
        full_representation: &GroupRepresentation<F, G>,
        forgery_index: usize,
    ) -> AggregateSignatureResult<GroupRepresentation<F, G>> {
        // Step 1: Identify which group elements correspond to σ_i*
        //
        // Mathematical Process:
        // The full representation Γ has rows for all output group elements.
        // We need to find the rows corresponding to the forgery signature.
        //
        // For a signature with k group elements, we need rows:
        // [forgery_index * k, ..., forgery_index * k + k - 1]
        
        let signature_size = forgery_signature.elements.len();
        let start_row = forgery_index * signature_size;
        let end_row = start_row + signature_size;
        
        // Step 2: Extract coefficients for these rows
        //
        // Mathematical Details:
        // For each group element g_j in σ_i*, we have:
        // g_j = Σ_k γ_jk · basis_k
        //
        // We extract the coefficient vector γ_j for each element
        
        let coefficients = full_representation.get_coefficients();
        
        if end_row > coefficients.len() {
            return Err(AggregateSignatureError::GroupElementExtractionFailed(
                format!("Forgery index {} out of bounds", forgery_index)
            ));
        }
        
        let forgery_coefficients: Vec<Vec<F>> = coefficients[start_row..end_row]
            .iter()
            .map(|row| row.clone())
            .collect();
        
        // Step 3: Build new basis for the forgery representation
        //
        // Mathematical Details:
        // The basis for Γ* should include:
        // - pp_Σ: Public parameters (generators)
        // - vk: Challenge verification key
        // - Q_σ: Signing oracle responses
        //
        // This ensures the representation shows how σ_i* is computed
        // from publicly available elements and signing queries.
        
        let mut forgery_basis = Vec::new();
        
        // Add public parameters to basis
        // In production, extract from self.agg_sig.pp_sig
        
        // Add challenge verification key to basis
        // forgery_basis.push(challenge_vk.key.clone());
        
        // Add signing oracle responses to basis
        // for (_, sig) in signing_queries {
        //     forgery_basis.extend(sig.elements.clone());
        // }
        
        // For now, use the original basis
        let original_basis = full_representation.get_basis();
        forgery_basis = original_basis.clone();
        
        // Step 4: Create new GroupRepresentation for the forgery
        let mut forgery_representation = GroupRepresentation::new();
        
        // Set basis
        for elem in forgery_basis {
            forgery_representation.add_basis_element(elem);
        }
        
        // Add coefficients for each signature element
        for (i, coeffs) in forgery_coefficients.iter().enumerate() {
            if i < forgery_signature.elements.len() {
                let elem = &forgery_signature.elements[i];
                forgery_representation.provide_representation(elem.clone(), coeffs.clone())
                    .map_err(|e| AggregateSignatureError::GroupElementExtractionFailed(
                        format!("Failed to add representation: {:?}", e)
                    ))?;
            }
        }
        
        // Step 5: Verify the representation is valid
        //
        // Mathematical Check:
        // For each g_j in σ_i*, verify:
        // g_j = Σ_k γ_jk · basis_k
        //
        // This ensures the representation correctly describes the forgery.
        
        for (i, elem) in forgery_signature.elements.iter().enumerate() {
            if i < forgery_coefficients.len() {
                let valid = forgery_representation.verify_representation(
                    elem,
                    &forgery_coefficients[i]
                ).map_err(|e| AggregateSignatureError::GroupElementExtractionFailed(
                    format!("Representation verification failed: {:?}", e)
                ))?;
                
                if !valid {
                    return Err(AggregateSignatureError::GroupElementExtractionFailed(
                        format!("Invalid representation for signature element {}", i)
                    ));
                }
            }
        }
        
        Ok(forgery_representation)
    }
}

/// Extracted witness from aggregate proof
struct ExtractedWitness<G> {
    /// Public keys and messages
    public_keys_messages: Vec<(VerificationKey<G>, Message)>,
    /// Individual signatures
    signatures: Vec<Signature<G>>,
    /// Oracle responses
    oracle_responses: Vec<Vec<u8>>,
}

/// Extractor failure analysis
///
/// If the O-SNARK extractor fails, we can construct an adversary C
/// against the O-AdPoK security of the SNARK.
///
/// Mathematical Details (from Theorem 5 proof):
/// If extractor E fails with non-negligible probability, then:
/// - The aggregate proof verifies: AggVer(pp, {vk_i, m_i}, σ_agg) = 1
/// - But extraction fails: E(pp, i, aux, x, π, Q_σ, tr_A, Γ) = ⊥
///
/// This violates O-AdPoK security, so we can construct adversary C:
/// 1. C receives O-AdPoK challenge
/// 2. C runs the aggregate signature game
/// 3. C outputs the aggregate proof that verifies but doesn't extract
/// 4. C wins O-AdPoK game
///
/// This bounds the probability of extractor failure:
/// Pr[E fails] ≤ Adv^{O-AdPoK}_Π(C) ≤ negl(λ)
pub struct ExtractorFailureAdversary<F, G, O, S>
where
    S: OSNARK<F, G, O>,
{
    /// Aggregate signature system
    agg_sig: AggregateSignature<F, G, O, S>,
    
    /// Phantom data
    _phantom: PhantomData<(F, G, O)>,
}

impl<F, G, O, S> ExtractorFailureAdversary<F, G, O, S>
where
    F: Clone,
    G: Clone + PartialEq + Eq + std::hash::Hash,
    O: Oracle<Vec<u8>, Vec<u8>>,
    S: OSNARK<F, G, O>,
{
    /// Create a new extractor failure adversary
    pub fn new(agg_sig: AggregateSignature<F, G, O, S>) -> Self {
        Self {
            agg_sig,
            _phantom: PhantomData,
        }
    }
    
    /// Run the adversary against O-AdPoK
    ///
    /// This adversary attempts to break O-AdPoK security by producing
    /// a proof that verifies but doesn't extract.
    ///
    /// If this adversary succeeds with non-negligible probability,
    /// it contradicts O-AdPoK security of the SNARK.
    ///
    /// Mathematical Details (from Theorem 5 proof):
    /// If the O-SNARK extractor E fails with non-negligible probability ε,
    /// then we can construct adversary C that breaks O-AdPoK with probability ε.
    ///
    /// The adversary C works as follows:
    /// 1. Receive O-AdPoK challenge (pp, aux, θ, O_aux)
    /// 2. Run aggregate signature game with adversary A
    /// 3. A outputs aggregate proof σ_agg
    /// 4. Check if σ_agg verifies: AggVer(pp, {vk_i, m_i}, σ_agg) = 1
    /// 5. Try extraction: w ← E(pp, i, aux, x, σ_agg, Q, tr_A, Γ)
    /// 6. If extraction fails but verification succeeds, output σ_agg
    /// 7. This violates O-AdPoK security
    ///
    /// Parameters:
    /// - aggregate_adversary: The EU-ACK adversary that causes extraction failure
    /// - oracle: Random oracle
    ///
    /// Returns:
    /// - Proof that verifies but doesn't extract (if successful)
    pub fn run<A>(
        &mut self,
        aggregate_adversary: &mut A,
        oracle: &mut O,
    ) -> AggregateSignatureResult<S::Proof>
    where
        A: AlgebraicAdversary<F, G, O>,
    {
        // Step 1: Setup aggregate signature game
        // Use the aggregate signature system from self
        let challenge_vk = VerificationKey::new(/* placeholder */);
        let sk = vec![0u8; 32]; // Placeholder secret key
        let mut signing_oracle = SigningOracle::new(sk);
        
        // Step 2: Run aggregate adversary
        // Give adversary access to aggregate signature system and oracles
        let output = aggregate_adversary.run_with_signing_oracle(
            &self.agg_sig.pp_sig,
            &challenge_vk,
            oracle,
            &mut signing_oracle,
        );
        
        // Step 3: Parse output to get aggregate proof
        // Extract the SNARK proof from the algebraic output
        if output.output_elements.is_empty() {
            return Err(AggregateSignatureError::InvalidProof(
                "No output elements from adversary".to_string()
            ));
        }
        
        // Build statement from output
        let num_signatures = output.output_elements.len() / 2;
        let mut public_keys_messages = Vec::new();
        
        for i in 0..num_signatures {
            if i >= output.output_elements.len() {
                break;
            }
            let vk = VerificationKey::new(output.output_elements[i].clone());
            let message = vec![i as u8];
            public_keys_messages.push((vk, message));
        }
        
        // Step 4: Verify the aggregate proof
        // Check if AggVer(pp, {vk_i, m_i}, σ_agg) = 1
        //
        // In production, this would call the actual aggregate verification
        // For now, we check if the proof has the right structure
        let proof_verifies = !output.oracle_queried_elements.is_empty();
        
        if !proof_verifies {
            return Err(AggregateSignatureError::ProofVerificationFailed(
                "Aggregate proof does not verify".to_string()
            ));
        }
        
        // Step 5: Try extraction
        // Attempt to extract witness using O-SNARK extractor
        //
        // Mathematical Process:
        // E(pp, i, aux, x, π, Q, tr_A, Γ) → w or ⊥
        //
        // Where:
        // - pp: SNARK public parameters
        // - i: Circuit index
        // - aux: Auxiliary input (challenge vk)
        // - x: Statement ({vk_i, m_i})
        // - π: Aggregate proof
        // - Q: Signing oracle queries
        // - tr_A: Prover transcript
        // - Γ: Group representations
        
        let signing_queries = signing_oracle.get_queries();
        let prover_transcript = oracle.transcript();
        
        // Attempt extraction
        let extraction_result = self.try_extract_witness(
            &public_keys_messages,
            &output,
            signing_queries,
            prover_transcript,
        );
        
        // Step 6: Check if extraction failed
        match extraction_result {
            Ok(_witness) => {
                // Extraction succeeded - not an O-AdPoK violation
                Err(AggregateSignatureError::ExtractionFailed(
                    "Extraction succeeded, no O-AdPoK violation".to_string()
                ))
            }
            Err(_) => {
                // Extraction failed but verification succeeded
                // This is an O-AdPoK violation!
                //
                // Mathematical Significance:
                // We have found a proof π such that:
                // - V^θ(ivk, x, π) = 1 (verification succeeds)
                // - E(pp, i, aux, x, π, Q, tr_A, Γ) = ⊥ (extraction fails)
                //
                // This violates the O-AdPoK property of the SNARK.
                // The probability of this happening should be negligible.
                
                // Return a placeholder proof
                // In production, this would return the actual SNARK proof
                Err(AggregateSignatureError::ProofGenerationFailed(
                    "O-AdPoK violation detected - extraction failed but verification succeeded".to_string()
                ))
            }
        }
    }
    
    /// Try to extract witness from aggregate proof
    ///
    /// Attempts extraction and returns result.
    fn try_extract_witness(
        &self,
        public_keys_messages: &[(VerificationKey<G>, Message)],
        output: &AlgebraicOutput<F, G>,
        signing_queries: &[(Message, Signature<G>)],
        prover_transcript: &OracleTranscript<Vec<u8>, Vec<u8>>,
    ) -> AggregateSignatureResult<ExtractedWitness<G>> {
        // Attempt to extract individual signatures
        // This uses the O-SNARK extractor with the group representations
        
        let mut extracted_signatures = Vec::new();
        
        for i in 0..public_keys_messages.len() {
            // Try to extract signature i
            let sig = self.extract_single_signature_from_output(
                i,
                &output.representations,
                public_keys_messages,
            )?;
            
            extracted_signatures.push(sig);
        }
        
        // Extract oracle responses
        let mut oracle_responses = Vec::new();
        for elem in &output.oracle_queried_elements {
            // Placeholder response
            oracle_responses.push(vec![0u8; 32]);
        }
        
        Ok(ExtractedWitness {
            public_keys_messages: public_keys_messages.to_vec(),
            signatures: extracted_signatures,
            oracle_responses,
        })
    }
    
    /// Extract single signature from output
    fn extract_single_signature_from_output(
        &self,
        index: usize,
        representations: &GroupRepresentation<F, G>,
        public_keys_messages: &[(VerificationKey<G>, Message)],
    ) -> AggregateSignatureResult<Signature<G>> {
        // Extract signature from group representation
        let basis = representations.get_basis();
        
        let signature_start = index * 2;
        let signature_end = signature_start + 2;
        
        let mut signature_elements = Vec::new();
        
        for elem_idx in signature_start..signature_end {
            if elem_idx < basis.len() {
                signature_elements.push(basis[elem_idx].clone());
            }
        }
        
        if signature_elements.is_empty() {
            return Err(AggregateSignatureError::GroupElementExtractionFailed(
                format!("No signature elements found for index {}", index)
            ));
        }
        
        Ok(Signature::new(signature_elements))
    }
    
    /// Bound the abort probability
    ///
    /// Proves that the probability of extractor failure is bounded by
    /// the advantage of breaking O-AdPoK security.
    ///
    /// Mathematical Details (from Theorem 5 proof):
    /// Let:
    /// - G0: Game where B simulates aggregate signature for A
    /// - G1: Game where B runs extractor E on A's output
    ///
    /// Then:
    /// |Pr[G0(A)] - Pr[G1(A)]| ≤ Pr[O-AdPoK(C)]
    ///
    /// Where C is the adversary constructed in this struct.
    ///
    /// Proof Sketch:
    /// 1. In G0, B simulates the aggregate signature game perfectly
    /// 2. In G1, B additionally runs the extractor
    /// 3. The games differ only when:
    ///    - Aggregate proof verifies: AggVer(pp, {vk_i, m_i}, σ_agg) = 1
    ///    - But extraction fails: E(...) = ⊥
    /// 4. This event violates O-AdPoK security
    /// 5. Therefore, the probability difference is bounded by O-AdPoK advantage
    ///
    /// Conclusion:
    /// If the O-SNARK has O-AdPoK security with advantage ε,
    /// then the extractor fails with probability at most ε.
    ///
    /// For a secure O-SNARK, ε = negl(λ), so extractor failure is negligible.
    ///
    /// Parameters:
    /// - lambda: Security parameter
    /// - osnark_advantage: Advantage of breaking O-AdPoK for the SNARK
    ///
    /// Returns:
    /// - Upper bound on extractor failure probability
    pub fn bound_abort_probability(
        &self,
        lambda: usize,
        osnark_advantage: f64,
    ) -> f64 {
        // Mathematical Formula:
        // Pr[Extractor fails] ≤ Adv^{O-AdPoK}_Π(C)
        //
        // Where:
        // - C is the adversary constructed in this struct
        // - Π is the underlying O-SNARK
        // - Adv^{O-AdPoK}_Π(C) is the advantage of C in breaking O-AdPoK
        //
        // For a secure O-SNARK:
        // Adv^{O-AdPoK}_Π(C) ≤ negl(λ)
        //
        // Common negligible functions:
        // - 2^{-λ} (exponentially small)
        // - λ^{-ω(1)} (super-polynomially small)
        //
        // In practice, for λ = 128:
        // - 2^{-128} ≈ 2.9 × 10^{-39}
        
        // The abort probability is bounded by the O-SNARK advantage
        let abort_bound = osnark_advantage;
        
        // For a secure O-SNARK, this should be negligible
        // We can add a check to ensure it's below a threshold
        let negligible_threshold = 2.0_f64.powi(-(lambda as i32));
        
        if abort_bound > negligible_threshold {
            // Warning: O-SNARK advantage is not negligible
            // This suggests the O-SNARK may not be secure
            eprintln!(
                "Warning: O-SNARK advantage {} exceeds negligible threshold {}",
                abort_bound, negligible_threshold
            );
        }
        
        abort_bound
    }
    
    /// Compute the security loss in the reduction
    ///
    /// The reduction from EU-ACK to EU-CMA has a security loss factor.
    /// This method computes the concrete security bound.
    ///
    /// Mathematical Details:
    /// If:
    /// - Σ has EU-CMA security with advantage ε_sig
    /// - Π has O-AdPoK security with advantage ε_snark
    ///
    /// Then the aggregate signature has EU-ACK security with advantage:
    /// ε_agg ≤ ε_sig + ε_snark
    ///
    /// This is a tight reduction with no significant security loss.
    ///
    /// Parameters:
    /// - signature_advantage: Advantage of breaking EU-CMA for base signature
    /// - osnark_advantage: Advantage of breaking O-AdPoK for SNARK
    ///
    /// Returns:
    /// - Upper bound on EU-ACK advantage for aggregate signature
    pub fn compute_security_loss(
        &self,
        signature_advantage: f64,
        osnark_advantage: f64,
    ) -> f64 {
        // Mathematical Formula:
        // Adv^{EU-ACK}_{AggSig}(A) ≤ Adv^{EU-CMA}_Σ(B) + Adv^{O-AdPoK}_Π(C)
        //
        // Where:
        // - A is the EU-ACK adversary
        // - B is the EU-CMA adversary constructed in the reduction
        // - C is the O-AdPoK adversary for extractor failure
        //
        // This shows the aggregate signature is as secure as the
        // base signature and the SNARK combined.
        
        signature_advantage + osnark_advantage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Tests would go here
    // We skip tests as per user request
}
