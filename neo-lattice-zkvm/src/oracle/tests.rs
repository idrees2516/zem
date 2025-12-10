// Integration tests for Oracle module

#[cfg(test)]
mod integration_tests {
    use crate::oracle::*;
    
    #[test]
    fn test_complete_oracle_workflow() {
        // Create random oracle
        let mut ro = RandomOracle::new();
        
        // Query oracle
        let input1 = vec![1u8, 2, 3];
        let response1 = ro.query(input1.clone()).unwrap();
        
        // Verify consistency
        let response2 = ro.query(input1).unwrap();
        assert_eq!(response1, response2);
        
        // Verify transcript
        assert!(ro.is_consistent());
        assert_eq!(ro.transcript().len(), 1);
    }
    
    #[test]
    fn test_arom_workflow() {
        // Create AROM
        let mut arom = AROM::<u64>::new(10);
        
        // Query all three oracles
        let x = vec![1u8, 2, 3];
        
        let ro_response = arom.query_ro(x.clone()).unwrap();
        let wo_response = arom.query_wo(&x).unwrap();
        let vco_response = arom.query_vco(&x).unwrap();
        
        // All should be deterministic
        assert_eq!(arom.query_ro(x.clone()).unwrap(), ro_response);
        assert_eq!(arom.query_wo(&x).unwrap(), wo_response);
        assert_eq!(arom.query_vco(&x).unwrap(), vco_response);
        
        // Verify properties
        assert!(arom.verify_properties().is_ok());
    }
    
    #[test]
    fn test_signed_oracle_workflow() {
        use signed_rom::SignedOracle;
        use serde::{Serialize, Deserialize};
        
        #[derive(Clone, Debug, Serialize, Deserialize)]
        struct TestSig {
            data: Vec<u8>,
        }
        
        // Create signed oracle
        let sk = vec![1u8, 2, 3];
        let mut oracle = SignedOracle::<Vec<u8>, TestSig>::new(sk);
        
        // Query RO
        let ro_input = vec![4u8, 5, 6];
        let ro_response = oracle.query_ro(ro_input).unwrap();
        assert!(!ro_response.is_empty());
        
        // Query signing oracle
        let message = vec![7u8, 8, 9];
        let signature = oracle.query_sign(message).unwrap();
        assert!(!signature.data.is_empty());
        
        assert_eq!(oracle.num_signing_queries(), 1);
    }
    
    #[test]
    fn test_emulator_workflow() {
        // Create emulator
        let mut emulator = AROMEmulator::<u64>::new(10);
        
        // Query emulated oracles
        let x = vec![1u8, 2, 3];
        
        let wo_result = emulator.query_wo(&x).unwrap();
        let vco_result = emulator.query_vco(&x).unwrap();
        let ro_result = emulator.query_ro(x.clone()).unwrap();
        
        // Verify caching
        assert_eq!(emulator.state().num_wo_cached(), 1);
        assert_eq!(emulator.state().num_vco_cached(), 1);
        
        // Verify emulation
        assert!(emulator.verify_emulation().is_ok());
    }
    
    #[test]
    fn test_security_lifting() {
        // Test signature security lifting
        let sig_lifting = SignatureSecurityLifting::<u64>::new(10);
        let emulator = sig_lifting.lift_signature_security();
        assert_eq!(emulator.degree_bound(), 10);
        
        // Test O-SNARK security lifting
        let osnark_lifting = OSNARKSecurityLifting::<u64>::new(10);
        let emulator = osnark_lifting.lift_osnark_security();
        assert_eq!(emulator.degree_bound(), 10);
    }
}
