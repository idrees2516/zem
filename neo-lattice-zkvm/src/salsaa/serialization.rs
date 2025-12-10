// SALSAA Proof Serialization
//
// Compact serialization for all proof structures with:
// - Variable-length encoding for integers
// - Run-length encoding for sparse data
// - Bit-level packing for flags and small values

use std::io::{self, Read, Write};
use crate::ring::cyclotomic::RingElement;
use crate::salsaa::{
    matrix::Matrix,
    applications::{
        snark_prover::SNARKProof,
        folding_prover::FoldingProof,
        pcs::OpeningProof,
    },
};

/// Compact proof encoder
pub struct CompactProofEncoder {
    /// Output buffer
    buffer: Vec<u8>,
}

impl CompactProofEncoder {
    /// Create new encoder
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }
    
    /// Encode variable-length integer
    pub fn encode_varint(&mut self, mut value: u64) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            
            if value != 0 {
                byte |= 0x80; // More bytes follow
            }
            
            self.buffer.push(byte);
            
            if value == 0 {
                break;
            }
        }
    }
    
    /// Encode ring element
    pub fn encode_ring_element(&mut self, elem: &RingElement) {
        // Encode length
        self.encode_varint(elem.coefficients.len() as u64);
        
        // Encode coefficients with run-length encoding for zeros
        let mut i = 0;
        while i < elem.coefficients.len() {
            if elem.coefficients[i] == 0 {
                // Count consecutive zeros
                let mut zero_count = 0;
                while i < elem.coefficients.len() && elem.coefficients[i] == 0 {
                    zero_count += 1;
                    i += 1;
                }
                
                // Encode zero run: 0x00 followed by count
                self.buffer.push(0x00);
                self.encode_varint(zero_count);
            } else {
                // Encode non-zero value
                let value = elem.coefficients[i];
                self.encode_signed_varint(value);
                i += 1;
            }
        }
    }
    
    /// Encode signed integer
    pub fn encode_signed_varint(&mut self, value: i64) {
        // ZigZag encoding: map signed to unsigned
        let encoded = if value >= 0 {
            (value as u64) << 1
        } else {
            (((-value) as u64) << 1) | 1
        };
        
        self.encode_varint(encoded);
    }
    
    /// Encode matrix
    pub fn encode_matrix(&mut self, matrix: &Matrix) {
        self.encode_varint(matrix.rows as u64);
        self.encode_varint(matrix.cols as u64);
        
        for elem in &matrix.data {
            self.encode_ring_element(elem);
        }
    }
    
    /// Encode vector of ring elements
    pub fn encode_ring_vector(&mut self, vec: &[RingElement]) {
        self.encode_varint(vec.len() as u64);
        for elem in vec {
            self.encode_ring_element(elem);
        }
    }
    
    /// Get encoded bytes
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }
}

/// Compact proof decoder
pub struct CompactProofDecoder<'a> {
    /// Input buffer
    buffer: &'a [u8],
    /// Current position
    pos: usize,
}

impl<'a> CompactProofDecoder<'a> {
    /// Create new decoder
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, pos: 0 }
    }
    
    /// Decode variable-length integer
    pub fn decode_varint(&mut self) -> io::Result<u64> {
        let mut result = 0u64;
        let mut shift = 0;
        
        loop {
            if self.pos >= self.buffer.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Buffer exhausted"));
            }
            
            let byte = self.buffer[self.pos];
            self.pos += 1;
            
            result |= ((byte & 0x7F) as u64) << shift;
            
            if (byte & 0x80) == 0 {
                break;
            }
            
            shift += 7;
            if shift >= 64 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Varint too large"));
            }
        }
        
        Ok(result)
    }
    
    /// Decode signed integer
    pub fn decode_signed_varint(&mut self) -> io::Result<i64> {
        let encoded = self.decode_varint()?;
        
        // ZigZag decoding
        let value = if (encoded & 1) == 0 {
            (encoded >> 1) as i64
        } else {
            -((encoded >> 1) as i64) - 1
        };
        
        Ok(value)
    }
    
    /// Decode ring element
    pub fn decode_ring_element(&mut self, ring: std::sync::Arc<crate::ring::cyclotomic::CyclotomicRing>) -> io::Result<RingElement> {
        let len = self.decode_varint()? as usize;
        let mut coefficients = Vec::with_capacity(len);
        
        while coefficients.len() < len {
            if self.pos >= self.buffer.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Buffer exhausted"));
            }
            
            if self.buffer[self.pos] == 0x00 {
                // Zero run
                self.pos += 1;
                let zero_count = self.decode_varint()? as usize;
                coefficients.extend(std::iter::repeat(0).take(zero_count));
            } else {
                // Non-zero value
                let value = self.decode_signed_varint()?;
                coefficients.push(value);
            }
        }
        
        Ok(RingElement {
            coefficients,
            ring,
        })
    }
    
    /// Decode matrix
    pub fn decode_matrix(&mut self, ring: std::sync::Arc<crate::ring::cyclotomic::CyclotomicRing>) -> io::Result<Matrix> {
        let rows = self.decode_varint()? as usize;
        let cols = self.decode_varint()? as usize;
        
        let mut data = Vec::with_capacity(rows * cols);
        for _ in 0..(rows * cols) {
            data.push(self.decode_ring_element(ring.clone())?);
        }
        
        Ok(Matrix::from_vec(rows, cols, data))
    }
    
    /// Decode vector of ring elements
    pub fn decode_ring_vector(&mut self, ring: std::sync::Arc<crate::ring::cyclotomic::CyclotomicRing>) -> io::Result<Vec<RingElement>> {
        let len = self.decode_varint()? as usize;
        let mut vec = Vec::with_capacity(len);
        
        for _ in 0..len {
            vec.push(self.decode_ring_element(ring.clone())?);
        }
        
        Ok(vec)
    }
}

/// Bit-level writer for compact encoding
pub struct BitWriter {
    buffer: Vec<u8>,
    current_byte: u8,
    bit_pos: u8,
}

impl BitWriter {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            current_byte: 0,
            bit_pos: 0,
        }
    }
    
    /// Write a single bit
    pub fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current_byte |= 1 << self.bit_pos;
        }
        
        self.bit_pos += 1;
        
        if self.bit_pos == 8 {
            self.buffer.push(self.current_byte);
            self.current_byte = 0;
            self.bit_pos = 0;
        }
    }
    
    /// Write multiple bits
    pub fn write_bits(&mut self, value: u64, num_bits: u8) {
        for i in 0..num_bits {
            self.write_bit((value >> i) & 1 == 1);
        }
    }
    
    /// Finish writing and get bytes
    pub fn finish(mut self) -> Vec<u8> {
        if self.bit_pos > 0 {
            self.buffer.push(self.current_byte);
        }
        self.buffer
    }
}

/// Bit-level reader
pub struct BitReader<'a> {
    buffer: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            byte_pos: 0,
            bit_pos: 0,
        }
    }
    
    /// Read a single bit
    pub fn read_bit(&mut self) -> io::Result<bool> {
        if self.byte_pos >= self.buffer.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Buffer exhausted"));
        }
        
        let bit = (self.buffer[self.byte_pos] >> self.bit_pos) & 1 == 1;
        
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.byte_pos += 1;
            self.bit_pos = 0;
        }
        
        Ok(bit)
    }
    
    /// Read multiple bits
    pub fn read_bits(&mut self, num_bits: u8) -> io::Result<u64> {
        let mut value = 0u64;
        
        for i in 0..num_bits {
            if self.read_bit()? {
                value |= 1 << i;
            }
        }
        
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_varint_encoding() {
        let mut encoder = CompactProofEncoder::new();
        
        encoder.encode_varint(0);
        encoder.encode_varint(127);
        encoder.encode_varint(128);
        encoder.encode_varint(16383);
        encoder.encode_varint(16384);
        
        let bytes = encoder.finish();
        let mut decoder = CompactProofDecoder::new(&bytes);
        
        assert_eq!(decoder.decode_varint().unwrap(), 0);
        assert_eq!(decoder.decode_varint().unwrap(), 127);
        assert_eq!(decoder.decode_varint().unwrap(), 128);
        assert_eq!(decoder.decode_varint().unwrap(), 16383);
        assert_eq!(decoder.decode_varint().unwrap(), 16384);
    }
    
    #[test]
    fn test_signed_varint() {
        let mut encoder = CompactProofEncoder::new();
        
        encoder.encode_signed_varint(0);
        encoder.encode_signed_varint(1);
        encoder.encode_signed_varint(-1);
        encoder.encode_signed_varint(100);
        encoder.encode_signed_varint(-100);
        
        let bytes = encoder.finish();
        let mut decoder = CompactProofDecoder::new(&bytes);
        
        assert_eq!(decoder.decode_signed_varint().unwrap(), 0);
        assert_eq!(decoder.decode_signed_varint().unwrap(), 1);
        assert_eq!(decoder.decode_signed_varint().unwrap(), -1);
        assert_eq!(decoder.decode_signed_varint().unwrap(), 100);
        assert_eq!(decoder.decode_signed_varint().unwrap(), -100);
    }
    
    #[test]
    fn test_bit_writer() {
        let mut writer = BitWriter::new();
        
        writer.write_bit(true);
        writer.write_bit(false);
        writer.write_bit(true);
        writer.write_bits(0b1010, 4);
        
        let bytes = writer.finish();
        let mut reader = BitReader::new(&bytes);
        
        assert_eq!(reader.read_bit().unwrap(), true);
        assert_eq!(reader.read_bit().unwrap(), false);
        assert_eq!(reader.read_bit().unwrap(), true);
        assert_eq!(reader.read_bits(4).unwrap(), 0b1010);
    }
}
