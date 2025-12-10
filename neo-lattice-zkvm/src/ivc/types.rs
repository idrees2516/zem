use serde::{Serialize, Deserialize};

/// IVC state z_i
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IVCState<F> {
    pub data: Vec<F>,
}

impl<F: Clone> IVCState<F> {
    pub fn new(data: Vec<F>) -> Self {
        Self { data }
    }
}

/// IVC witness (w_i, z_{i-1}, π_{i-1}, r)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IVCWitness<F, P> {
    pub w_local: Vec<F>,
    pub z_prev: Vec<F>,
    pub proof_prev: Option<P>,
    pub oracle_responses: Vec<Vec<u8>>,
}

/// IVC proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IVCProof {
    pub data: Vec<u8>,
}
