// Proof Serialization with Versioning
// Task 18.6: Implement proof serialization with versioning
//
// This module provides versioned serialization for all proof types,
// ensuring forward and backward compatibility.
//
// Design Principles:
// 1. Version prefix: All serialized proofs start with version number
// 2. Length prefixes: All variable-length fields have length prefix
// 3. Type tags: Discriminate between proof types
// 4. Extensibility: New versions can add fields without breaking old parsers
//
// Serialization Format:
// [version: u32][type_tag: u8][length: u64][data: bytes]
//
// Supported Proof Types:
// - IVC proofs
// - PCD proofs
// - SNARK proofs
// - Folding proofs
// - Sum-check proofs

use std::io::{Read, Write, Cursor};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{Serialize, Deserialize};

/// Current serialization version
pub const CURRENT_VERSION: u32 = 1;

/// Proof type tags
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofType {
    /// IVC proof
    IVC = 0,
    
    /// PCD proof
    PCD = 1,
    
    /// SNARK proof
    SNARK = 2,
    
    /// Neo folding proof
    NeoFolding = 3,
    
    /// SALSAA sum-check proof
    SALSAASumCheck = 4,
    
    /// Quasar accumulation proof
    QuasarAccumulation = 5,
    
    /// Symphony high-arity folding proof
    SymphonyFolding = 6,
}

impl ProofType {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(Self::IVC),
            1 => Ok(Self::PCD),
            2 => Ok(Self::SNARK),
            3 => Ok(Self::NeoFolding),
            4 => Ok(Self::SALSAASumCheck),
            5 => Ok(Self::QuasarAccumulation),
            6 => Ok(Self::SymphonyFolding),
            _ => Err(format!("Unknown proof type: {}", value)),
        }
    }
}

/// Serialization error
#[derive(Debug)]
pub enum SerializationError {
    /// IO error
    IoError(std::io::Error),
    
    /// Invalid version
    InvalidVersion(u32),
    
    /// Invalid proof type
    InvalidProofType(u8),
    
    /// Invalid length
    InvalidLength(u64),
    
    /// Deserialization error
    DeserializationError(String),
}

impl From<std::io::Error> for SerializationError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl std::fmt::Display for SerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::InvalidVersion(v) => write!(f, "Invalid version: {}", v),
            Self::InvalidProofType(t) => write!(f, "Invalid proof type: {}", t),
            Self::InvalidLength(l) => write!(f, "Invalid length: {}", l),
            Self::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
        }
    }
}

impl std::error::Error for SerializationError {}

pub type SerializationResult<T> = Result<T, SerializationError>;

/// Proof serializer
///
/// Handles versioned serialization of proofs.
pub struct ProofSerializer {
    /// Version to use for serialization
    version: u32,
}

impl ProofSerializer {
    /// Create new serializer with current version
    pub fn new() -> Self {
        Self {
            version: CURRENT_VERSION,
        }
    }
    
    /// Create serializer with specific version
    pub fn with_version(version: u32) -> Self {
        Self { version }
    }
    
    /// Serialize proof to bytes
    ///
    /// Format:
    /// [version: u32][type_tag: u8][length: u64][data: bytes]
    ///
    /// Parameters:
    /// - proof_type: Type of proof
    /// - data: Proof data
    ///
    /// Returns:
    /// - Serialized bytes
    pub fn serialize(
        &self,
        proof_type: ProofType,
        data: &[u8],
    ) -> SerializationResult<Vec<u8>> {
        let mut buffer = Vec::new();
        
        // Write version
        buffer.write_u32::<LittleEndian>(self.version)?;
        
        // Write proof type
        buffer.write_u8(proof_type as u8)?;
        
        // Write length
        buffer.write_u64::<LittleEndian>(data.len() as u64)?;
        
        // Write data
        buffer.write_all(data)?;
        
        Ok(buffer)
    }
    
    /// Serialize with metadata
    ///
    /// Includes additional metadata fields:
    /// - timestamp: Unix timestamp
    /// - security_level: Security parameter λ
    /// - custom_metadata: Application-specific data
    pub fn serialize_with_metadata(
        &self,
        proof_type: ProofType,
        data: &[u8],
        metadata: &ProofMetadata,
    ) -> SerializationResult<Vec<u8>> {
        let mut buffer = Vec::new();
        
        // Write version
        buffer.write_u32::<LittleEndian>(self.version)?;
        
        // Write proof type
        buffer.write_u8(proof_type as u8)?;
        
        // Write metadata flag (1 = has metadata)
        buffer.write_u8(1)?;
        
        // Serialize metadata
        let metadata_bytes = bincode::serialize(metadata)
            .map_err(|e| SerializationError::DeserializationError(e.to_string()))?;
        buffer.write_u64::<LittleEndian>(metadata_bytes.len() as u64)?;
        buffer.write_all(&metadata_bytes)?;
        
        // Write proof data length
        buffer.write_u64::<LittleEndian>(data.len() as u64)?;
        
        // Write proof data
        buffer.write_all(data)?;
        
        Ok(buffer)
    }
    
    /// Deserialize proof from bytes
    ///
    /// Returns:
    /// - (version, proof_type, data)
    pub fn deserialize(
        &self,
        bytes: &[u8],
    ) -> SerializationResult<(u32, ProofType, Vec<u8>)> {
        let mut cursor = Cursor::new(bytes);
        
        // Read version
        let version = cursor.read_u32::<LittleEndian>()?;
        
        // Validate version
        if version > CURRENT_VERSION {
            return Err(SerializationError::InvalidVersion(version));
        }
        
        // Read proof type
        let type_tag = cursor.read_u8()?;
        let proof_type = ProofType::from_u8(type_tag)
            .map_err(|_| SerializationError::InvalidProofType(type_tag))?;
        
        // Read length
        let length = cursor.read_u64::<LittleEndian>()?;
        
        // Validate length
        if length > bytes.len() as u64 {
            return Err(SerializationError::InvalidLength(length));
        }
        
        // Read data
        let mut data = vec![0u8; length as usize];
        cursor.read_exact(&mut data)?;
        
        Ok((version, proof_type, data))
    }
    
    /// Deserialize with metadata
    ///
    /// Returns:
    /// - (version, proof_type, metadata, data)
    pub fn deserialize_with_metadata(
        &self,
        bytes: &[u8],
    ) -> SerializationResult<(u32, ProofType, Option<ProofMetadata>, Vec<u8>)> {
        let mut cursor = Cursor::new(bytes);
        
        // Read version
        let version = cursor.read_u32::<LittleEndian>()?;
        
        // Validate version
        if version > CURRENT_VERSION {
            return Err(SerializationError::InvalidVersion(version));
        }
        
        // Read proof type
        let type_tag = cursor.read_u8()?;
        let proof_type = ProofType::from_u8(type_tag)
            .map_err(|_| SerializationError::InvalidProofType(type_tag))?;
        
        // Read metadata flag
        let has_metadata = cursor.read_u8()? == 1;
        
        let metadata = if has_metadata {
            // Read metadata length
            let metadata_len = cursor.read_u64::<LittleEndian>()?;
            
            // Read metadata
            let mut metadata_bytes = vec![0u8; metadata_len as usize];
            cursor.read_exact(&mut metadata_bytes)?;
            
            let metadata: ProofMetadata = bincode::deserialize(&metadata_bytes)
                .map_err(|e| SerializationError::DeserializationError(e.to_string()))?;
            
            Some(metadata)
        } else {
            None
        };
        
        // Read proof data length
        let data_len = cursor.read_u64::<LittleEndian>()?;
        
        // Read proof data
        let mut data = vec![0u8; data_len as usize];
        cursor.read_exact(&mut data)?;
        
        Ok((version, proof_type, metadata, data))
    }
    
    /// Get version
    pub fn version(&self) -> u32 {
        self.version
    }
}

impl Default for ProofSerializer {
    fn default() -> Self {
        Self::new()
    }
}

/// Proof metadata
///
/// Additional information about the proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Unix timestamp when proof was generated
    pub timestamp: u64,
    
    /// Security level λ in bits
    pub security_level: u32,
    
    /// Prover ID (optional)
    pub prover_id: Option<String>,
    
    /// Application-specific metadata
    pub custom: Vec<u8>,
}

impl ProofMetadata {
    /// Create new metadata
    pub fn new(security_level: u32) -> Self {
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            security_level,
            prover_id: None,
            custom: Vec::new(),
        }
    }
    
    /// Set prover ID
    pub fn with_prover_id(mut self, id: String) -> Self {
        self.prover_id = Some(id);
        self
    }
    
    /// Set custom metadata
    pub fn with_custom(mut self, data: Vec<u8>) -> Self {
        self.custom = data;
        self
    }
}

/// Batch proof serializer
///
/// Efficiently serializes multiple proofs together.
pub struct BatchProofSerializer {
    /// Base serializer
    serializer: ProofSerializer,
}

impl BatchProofSerializer {
    /// Create new batch serializer
    pub fn new() -> Self {
        Self {
            serializer: ProofSerializer::new(),
        }
    }
    
    /// Serialize batch of proofs
    ///
    /// Format:
    /// [version: u32][count: u64]
    /// [type_1: u8][length_1: u64][data_1: bytes]
    /// [type_2: u8][length_2: u64][data_2: bytes]
    /// ...
    ///
    /// Parameters:
    /// - proofs: Vector of (proof_type, data) pairs
    ///
    /// Returns:
    /// - Serialized bytes
    pub fn serialize_batch(
        &self,
        proofs: &[(ProofType, Vec<u8>)],
    ) -> SerializationResult<Vec<u8>> {
        let mut buffer = Vec::new();
        
        // Write version
        buffer.write_u32::<LittleEndian>(CURRENT_VERSION)?;
        
        // Write count
        buffer.write_u64::<LittleEndian>(proofs.len() as u64)?;
        
        // Write each proof
        for (proof_type, data) in proofs {
            // Write type
            buffer.write_u8(*proof_type as u8)?;
            
            // Write length
            buffer.write_u64::<LittleEndian>(data.len() as u64)?;
            
            // Write data
            buffer.write_all(data)?;
        }
        
        Ok(buffer)
    }
    
    /// Deserialize batch of proofs
    ///
    /// Returns:
    /// - Vector of (proof_type, data) pairs
    pub fn deserialize_batch(
        &self,
        bytes: &[u8],
    ) -> SerializationResult<Vec<(ProofType, Vec<u8>)>> {
        let mut cursor = Cursor::new(bytes);
        
        // Read version
        let version = cursor.read_u32::<LittleEndian>()?;
        if version > CURRENT_VERSION {
            return Err(SerializationError::InvalidVersion(version));
        }
        
        // Read count
        let count = cursor.read_u64::<LittleEndian>()?;
        
        let mut proofs = Vec::with_capacity(count as usize);
        
        // Read each proof
        for _ in 0..count {
            // Read type
            let type_tag = cursor.read_u8()?;
            let proof_type = ProofType::from_u8(type_tag)
                .map_err(|_| SerializationError::InvalidProofType(type_tag))?;
            
            // Read length
            let length = cursor.read_u64::<LittleEndian>()?;
            
            // Read data
            let mut data = vec![0u8; length as usize];
            cursor.read_exact(&mut data)?;
            
            proofs.push((proof_type, data));
        }
        
        Ok(proofs)
    }
}

impl Default for BatchProofSerializer {
    fn default() -> Self {
        Self::new()
    }
}

/// Compressed proof serializer
///
/// Uses compression to reduce proof size.
pub struct CompressedProofSerializer {
    /// Base serializer
    serializer: ProofSerializer,
    
    /// Compression level (0-9)
    compression_level: u32,
}

impl CompressedProofSerializer {
    /// Create new compressed serializer
    ///
    /// Parameters:
    /// - compression_level: 0 (no compression) to 9 (maximum compression)
    pub fn new(compression_level: u32) -> Self {
        Self {
            serializer: ProofSerializer::new(),
            compression_level: compression_level.min(9),
        }
    }
    
    /// Serialize with compression
    ///
    /// Format:
    /// [version: u32][type: u8][compressed_flag: u8][original_length: u64][compressed_length: u64][data: bytes]
    pub fn serialize_compressed(
        &self,
        proof_type: ProofType,
        data: &[u8],
    ) -> SerializationResult<Vec<u8>> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        
        let mut buffer = Vec::new();
        
        // Write version
        buffer.write_u32::<LittleEndian>(CURRENT_VERSION)?;
        
        // Write proof type
        buffer.write_u8(proof_type as u8)?;
        
        // Write compressed flag
        buffer.write_u8(1)?;
        
        // Write original length
        buffer.write_u64::<LittleEndian>(data.len() as u64)?;
        
        // Compress data
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(self.compression_level));
        encoder.write_all(data)?;
        let compressed = encoder.finish()?;
        
        // Write compressed length
        buffer.write_u64::<LittleEndian>(compressed.len() as u64)?;
        
        // Write compressed data
        buffer.write_all(&compressed)?;
        
        Ok(buffer)
    }
    
    /// Deserialize compressed proof
    pub fn deserialize_compressed(
        &self,
        bytes: &[u8],
    ) -> SerializationResult<(ProofType, Vec<u8>)> {
        use flate2::read::ZlibDecoder;
        
        let mut cursor = Cursor::new(bytes);
        
        // Read version
        let version = cursor.read_u32::<LittleEndian>()?;
        if version > CURRENT_VERSION {
            return Err(SerializationError::InvalidVersion(version));
        }
        
        // Read proof type
        let type_tag = cursor.read_u8()?;
        let proof_type = ProofType::from_u8(type_tag)
            .map_err(|_| SerializationError::InvalidProofType(type_tag))?;
        
        // Read compressed flag
        let is_compressed = cursor.read_u8()? == 1;
        
        if !is_compressed {
            return Err(SerializationError::DeserializationError(
                "Expected compressed proof".to_string()
            ));
        }
        
        // Read original length
        let original_length = cursor.read_u64::<LittleEndian>()?;
        
        // Read compressed length
        let compressed_length = cursor.read_u64::<LittleEndian>()?;
        
        // Read compressed data
        let mut compressed = vec![0u8; compressed_length as usize];
        cursor.read_exact(&mut compressed)?;
        
        // Decompress
        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        
        // Verify length
        if decompressed.len() != original_length as usize {
            return Err(SerializationError::InvalidLength(original_length));
        }
        
        Ok((proof_type, decompressed))
    }
}
