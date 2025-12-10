// Oracle Transcript Management
//
// Implements transcript tracking for oracle queries and responses.
// Maintains the constraint that oracle responses are consistent across repeated queries.
//
// Mathematical Foundation:
// - Oracle transcript tr_A = {(q_i, r_i)} records all queries and responses
// - Consistency: θ(q) must return same r for repeated queries

use std::collections::HashMap;
use std::hash::Hash;
use serde::{Serialize, Deserialize};

use super::errors::{OracleError, OracleResult};

/// A single oracle query-response pair
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OracleQuery<X, Y> {
    /// Query input
    pub query: X,
    
    /// Oracle response
    pub response: Y,
    
    /// Query index (order in transcript)
    pub index: usize,
}

impl<X, Y> OracleQuery<X, Y> {
    /// Create a new oracle query
    pub fn new(query: X, response: Y, index: usize) -> Self {
        Self {
            query,
            response,
            index,
        }
    }
}

/// Oracle transcript containing all query-response pairs
///
/// Maintains consistency: repeated queries must return the same response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleTranscript<X, Y>
where
    X: Clone + Eq + Hash,
    Y: Clone + Eq,
{
    /// List of all queries in order
    queries: Vec<OracleQuery<X, Y>>,
    
    /// Map from query to response (for consistency checking)
    query_map: HashMap<X, Y>,
}

impl<X, Y> OracleTranscript<X, Y>
where
    X: Clone + Eq + Hash,
    Y: Clone + Eq,
{
    /// Create a new empty transcript
    pub fn new() -> Self {
        Self {
            queries: Vec::new(),
            query_map: HashMap::new(),
        }
    }
    
    /// Record a query-response pair
    ///
    /// # Arguments
    /// * `query` - The query input
    /// * `response` - The oracle response
    ///
    /// # Returns
    /// Ok(()) if successful, Err if query already exists with different response
    pub fn record(&mut self, query: X, response: Y) -> OracleResult<()> {
        // Check consistency
        if let Some(existing_response) = self.query_map.get(&query) {
            if existing_response != &response {
                return Err(OracleError::InconsistentTranscript);
            }
            // Query already recorded with same response, no need to add again
            return Ok(());
        }
        
        // Add to transcript
        let index = self.queries.len();
        self.queries.push(OracleQuery::new(query.clone(), response.clone(), index));
        self.query_map.insert(query, response);
        
        Ok(())
    }
    
    /// Get response for a query (if it exists in transcript)
    pub fn get_response(&self, query: &X) -> Option<&Y> {
        self.query_map.get(query)
    }
    
    /// Check if a query exists in the transcript
    pub fn contains_query(&self, query: &X) -> bool {
        self.query_map.contains_key(query)
    }
    
    /// Get all queries in order
    pub fn queries(&self) -> &[OracleQuery<X, Y>] {
        &self.queries
    }
    
    /// Get number of queries
    pub fn len(&self) -> usize {
        self.queries.len()
    }
    
    /// Check if transcript is empty
    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }
    
    /// Verify transcript consistency
    ///
    /// Checks that all queries in the list match the query map
    pub fn verify_consistency(&self) -> OracleResult<()> {
        for query_entry in &self.queries {
            if let Some(mapped_response) = self.query_map.get(&query_entry.query) {
                if mapped_response != &query_entry.response {
                    return Err(OracleError::InconsistentTranscript);
                }
            } else {
                return Err(OracleError::InconsistentTranscript);
            }
        }
        Ok(())
    }
    
    /// Clear the transcript
    pub fn clear(&mut self) {
        self.queries.clear();
        self.query_map.clear();
    }
    
    /// Merge another transcript into this one
    ///
    /// # Returns
    /// Err if there are conflicting query-response pairs
    pub fn merge(&mut self, other: &OracleTranscript<X, Y>) -> OracleResult<()> {
        for query_entry in &other.queries {
            self.record(query_entry.query.clone(), query_entry.response.clone())?;
        }
        Ok(())
    }
}

impl<X, Y> Default for OracleTranscript<X, Y>
where
    X: Clone + Eq + Hash,
    Y: Clone + Eq,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for oracle implementations
///
/// An oracle θ: X → Y that maintains a transcript of all queries
pub trait Oracle<X, Y>
where
    X: Clone + Eq + Hash,
    Y: Clone + Eq,
{
    /// Query the oracle with input
    ///
    /// # Arguments
    /// * `input` - The query input
    ///
    /// # Returns
    /// The oracle response
    fn query(&mut self, input: X) -> OracleResult<Y>;
    
    /// Get the full transcript
    fn transcript(&self) -> &OracleTranscript<X, Y>;
    
    /// Get mutable transcript (for advanced use)
    fn transcript_mut(&mut self) -> &mut OracleTranscript<X, Y>;
    
    /// Check if oracle is consistent
    ///
    /// Verifies that all queries return consistent responses
    fn is_consistent(&self) -> bool {
        self.transcript().verify_consistency().is_ok()
    }
    
    /// Reset the oracle (clear transcript)
    fn reset(&mut self) {
        self.transcript_mut().clear();
    }
}

/// Helper trait for cloning oracles
pub trait CloneableOracle<X, Y>: Oracle<X, Y>
where
    X: Clone + Eq + Hash,
    Y: Clone + Eq,
{
    /// Clone the oracle
    fn clone_oracle(&self) -> Box<dyn CloneableOracle<X, Y>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_transcript_creation() {
        let transcript = OracleTranscript::<Vec<u8>, Vec<u8>>::new();
        assert_eq!(transcript.len(), 0);
        assert!(transcript.is_empty());
    }
    
    #[test]
    fn test_record_query() {
        let mut transcript = OracleTranscript::new();
        
        let query = vec![1u8, 2, 3];
        let response = vec![4u8, 5, 6];
        
        assert!(transcript.record(query.clone(), response.clone()).is_ok());
        assert_eq!(transcript.len(), 1);
        assert_eq!(transcript.get_response(&query), Some(&response));
    }
    
    #[test]
    fn test_consistency_check() {
        let mut transcript = OracleTranscript::new();
        
        let query = vec![1u8, 2, 3];
        let response1 = vec![4u8, 5, 6];
        let response2 = vec![7u8, 8, 9];
        
        // First query
        assert!(transcript.record(query.clone(), response1.clone()).is_ok());
        
        // Same query with same response should be ok
        assert!(transcript.record(query.clone(), response1.clone()).is_ok());
        assert_eq!(transcript.len(), 1); // Should not add duplicate
        
        // Same query with different response should fail
        assert!(transcript.record(query.clone(), response2).is_err());
    }
    
    #[test]
    fn test_verify_consistency() {
        let mut transcript = OracleTranscript::new();
        
        transcript.record(vec![1u8], vec![2u8]).unwrap();
        transcript.record(vec![3u8], vec![4u8]).unwrap();
        
        assert!(transcript.verify_consistency().is_ok());
    }
    
    #[test]
    fn test_merge_transcripts() {
        let mut transcript1 = OracleTranscript::new();
        transcript1.record(vec![1u8], vec![2u8]).unwrap();
        
        let mut transcript2 = OracleTranscript::new();
        transcript2.record(vec![3u8], vec![4u8]).unwrap();
        
        assert!(transcript1.merge(&transcript2).is_ok());
        assert_eq!(transcript1.len(), 2);
    }
    
    #[test]
    fn test_merge_conflicting_transcripts() {
        let mut transcript1 = OracleTranscript::new();
        transcript1.record(vec![1u8], vec![2u8]).unwrap();
        
        let mut transcript2 = OracleTranscript::new();
        transcript2.record(vec![1u8], vec![99u8]).unwrap(); // Conflicting response
        
        assert!(transcript1.merge(&transcript2).is_err());
    }
}
