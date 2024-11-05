// src/pow.rs

use argon2::{Argon2, Params as Argon2Params, Version};
use serde::Serialize;

/// Enum defining different Proof of Work (PoW) algorithms.
#[allow(non_camel_case_types)]
pub enum PoWAlgorithm {
    Argon2id(Argon2Params),
}

impl PoWAlgorithm {

    /// Calculates Argon2id hash with given data and nonce.
    pub fn calculate_argon2id(data: &[u8], nonce: u64, params: &Argon2Params) -> Vec<u8> {
        let mut output = vec![0u8; 32];
        let salt = nonce.to_le_bytes();

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            Version::V0x13,
            params.clone(),
        );

        argon2
            .hash_password_into(data, &salt, &mut output)
            .unwrap();

        output
    }

    /// Calculates hash based on the selected algorithm.
    pub fn calculate(&self, data: &[u8], nonce: u64) -> Vec<u8> {
        match self {
            Self::Argon2id(params) => Self::calculate_argon2id(data, nonce, params),
        }
    }
}

/// Struct representing Proof of Work (PoW) with data, difficulty, and algorithm.
pub struct PoW {
    data: Vec<u8>,
    difficulty: usize,
    algorithm: PoWAlgorithm,
}

impl PoW {
    /// Creates a new instance of PoW with serialized data, difficulty, and algorithm.
    pub fn new(
        data: impl Serialize,
        difficulty: usize,
        algorithm: PoWAlgorithm,
    ) -> Result<Self, serde_json::Error> {
        Ok(PoW {
            data: serde_json::to_vec(&data)?,
            difficulty,
            algorithm,
        })
    }

    /// Calculates the target hash prefix based on the difficulty.
    pub fn calculate_target(&self) -> Vec<u8> {
        // Each difficulty level increases the number of leading zeros in the hash.
        vec![0u8; self.difficulty]
    }

    /// Calculates PoW with the given target hash prefix.
    pub fn calculate_pow(&self) -> (Vec<u8>, u64) {
        let target = self.calculate_target();
        let mut nonce = 0u64;

        loop {
            let hash = self.algorithm.calculate(&self.data, nonce);
            
            if hash.starts_with(&target) {
                return (hash, nonce);
            }

            nonce += 1;
        }
    }

    /// Verifies PoW with the given hash and nonce.
    pub fn verify_pow(&self, hash: &[u8], nonce: u64) -> bool {
        let target = self.calculate_target();
        let calculated_hash = self.algorithm.calculate(&self.data, nonce);

        calculated_hash.starts_with(&target) && calculated_hash == hash
    }
}
