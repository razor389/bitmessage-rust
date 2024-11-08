// src/packet.rs
use zstd::stream::encode_all;
use zstd::stream::decode_all;

use serde::{Serialize, Deserialize};
use ed25519_dalek::{Signature, VerifyingKey};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::{authentication::Authentication, encryption::Encryption, pow::{PoW, PoWAlgorithm}, serializable_argon2_params::SerializableArgon2Params};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
#[allow(unused_imports)]
use log::{info, debug, warn, error};

pub const ADDRESS_LENGTH: usize = 20; // For example, 20 bytes (160 bits)
pub type Address = [u8; ADDRESS_LENGTH];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Packet {
    pub signing_public_key: [u8; 32],
    pub dh_public_key: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>, 
    pub pow_nonce: u64,
    pub pow_hash: Vec<u8>,
    pub recipient_address: Address,
    pub timestamp: u64, // UNIX timestamp in seconds
    pub ttl: u64,       // Time to live in seconds
    pub argon2_params: SerializableArgon2Params,
}

impl Packet {
    pub fn new(
        signing_public_key: [u8; 32],
        dh_public_key: [u8; 32],
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
        pow_nonce: u64,
        pow_hash: Vec<u8>,
        recipient_address: Address, // Added recipient_address
        timestamp: u64,
        ttl: u64,
        argon2_params: SerializableArgon2Params,
    ) -> Self {
        Packet {
            signing_public_key,
            dh_public_key,
            nonce,
            ciphertext,
            signature,
            pow_nonce,
            pow_hash,
            recipient_address, // Added recipient_address
            timestamp,
            ttl,
            argon2_params,
        }
    }

    pub fn compute_address(&self) -> Address {
        let mut hasher = Sha256::new();
        hasher.update(&self.signing_public_key);
        hasher.update(&self.dh_public_key);
        let result = hasher.finalize();
        let mut address = [0u8; ADDRESS_LENGTH];
        address.copy_from_slice(&result[..ADDRESS_LENGTH]);
        address
    }

    pub fn serialize(&self) -> Vec<u8> {
        let serialized_data = bincode::serialize(&self).expect("Failed to serialize packet");

        let compression_level = 0; // Adjust between -5 (fastest) and 22 (best compression)
        let compressed_data = encode_all(&serialized_data[..], compression_level).expect("Failed to compress data");

        compressed_data
    }

    pub fn deserialize(data: &[u8]) -> Packet {
        let decompressed_data = decode_all(&data[..]).expect("Failed to decompress data");

        bincode::deserialize(&decompressed_data).expect("Failed to deserialize packet")
    }

    pub fn create_signed_encrypted(
        auth: &Authentication,
        encryption: &Encryption,
        recipient_public_key: &X25519PublicKey,
        recipient_address: Address,
        message: &[u8],
        pow_difficulty: usize,
        ttl: u64,
        argon2_params: SerializableArgon2Params,
    ) -> Self {
        info!("Creating signed and encrypted packet");

        // **Compress the message before signing and encrypting**
        let compression_level = 0; // Adjust as needed
        let compressed_message =
            encode_all(&message[..], compression_level).expect("Failed to compress message");

        // Step 1: Sign the compressed message
        let signature = auth
            .sign_message(&compressed_message)
            .to_bytes()
            .to_vec();

        // Step 2: Encrypt the compressed message
        let (ciphertext, nonce) =
            encryption.encrypt_message(recipient_public_key, &compressed_message);

        // Step 3: Prepare the Packet data for PoW (excluding pow_nonce and pow_hash)
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let mut packet = Packet {
            signing_public_key: auth.verifying_key().to_bytes(),
            dh_public_key: *encryption.our_public_key.as_bytes(),
            nonce,
            ciphertext,
            signature,
            pow_nonce: 0,
            pow_hash: Vec::new(),
            recipient_address,
            timestamp,
            ttl,
            argon2_params: argon2_params.clone(),
        };

        let packet_data = packet.serialize();

        // Step 4: Perform PoW
        let argon2_params_native = argon2_params.to_argon2_params();

        let pow = PoW::new(
            &packet_data,
            pow_difficulty,
            PoWAlgorithm::Argon2id(argon2_params_native),
        )
        .unwrap();

        let (pow_hash, pow_nonce) = pow.calculate_pow();

        // Step 5: Update Packet with PoW results
        packet.pow_nonce = pow_nonce;
        packet.pow_hash = pow_hash;

        packet
    }

    pub fn verify_and_decrypt(
        &self,
        encryption: &Encryption,
        sender_public_key: &X25519PublicKey,
        pow_difficulty: usize,
    ) -> Option<Vec<u8>> {
        info!(
            "Verifying and decrypting packet destined for address {:?}",
            self.recipient_address
        );
        // Step 1: Verify PoW
        let packet_without_pow = Packet {
            pow_nonce: 0,
            pow_hash: Vec::new(),
            ..self.clone()
        };

        let packet_data = packet_without_pow.serialize();

        let argon2_params_native = self.argon2_params.to_argon2_params();

        let pow = PoW::new(
            &packet_data,
            pow_difficulty,
            PoWAlgorithm::Argon2id(argon2_params_native),
        )
        .unwrap();

        if !pow.verify_pow(&self.pow_hash, self.pow_nonce) {
            return None;
        }

        // Step 2: Decrypt the message
        let decrypted_compressed_message =
            encryption.decrypt_message(sender_public_key, &self.nonce, &self.ciphertext);

        // **Step 3: Verify the signature over the compressed message**
        let verifying_key = VerifyingKey::from_bytes(&self.signing_public_key).ok()?;

        let signature_bytes: &[u8; 64] = self.signature.as_slice().try_into().ok()?;
        let signature = Signature::from_bytes(signature_bytes);

        if !Authentication::verify_message_with_key(
            &decrypted_compressed_message,
            &signature,
            &verifying_key,
        ) {
            return None;
        }

        // **Step 4: Decompress the decrypted message**
        let decompressed_message = decode_all(&decrypted_compressed_message[..]).ok()?;

        Some(decompressed_message)
    }

    pub fn verify_pow(&self, pow_difficulty: usize) -> bool {
        // Reconstruct the packet data without PoW fields
        let packet_without_pow = Packet {
            pow_nonce: 0,
            pow_hash: Vec::new(),
            ..self.clone()
        };

        let packet_data = packet_without_pow.serialize();

        let argon2_params_native = self.argon2_params.to_argon2_params();

        let pow = PoW::new(
            &packet_data,
            pow_difficulty,
            PoWAlgorithm::Argon2id(argon2_params_native),
        )
        .unwrap();

        pow.verify_pow(&self.pow_hash, self.pow_nonce)
    }
}
