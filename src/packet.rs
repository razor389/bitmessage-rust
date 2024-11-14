// src/packet.rs
use zstd::stream::encode_all;
use zstd::stream::decode_all;

use serde::{Serialize, Deserialize};
use ed25519_dalek::{Signature, VerifyingKey};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::{authentication::Authentication, encryption::Encryption, pow::{PoW, PoWAlgorithm}, serializable_argon2_params::SerializableArgon2Params};
use std::time::{SystemTime, UNIX_EPOCH};
#[allow(unused_imports)]
use log::{info, debug, warn, error};

pub const ADDRESS_LENGTH: usize = 20; // For example, 20 bytes (160 bits)
pub type Address = [u8; ADDRESS_LENGTH];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Packet {
    pub ephemeral_dh_public_key: [u8; 32], // Sender's ephemeral DH public key
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub pow_nonce: u64,
    pub pow_hash: Vec<u8>,
    pub pow_difficulty: usize,
    pub recipient_address: Address,
    pub timestamp: u64, // UNIX timestamp in seconds
    pub ttl: u64,       // Time to live in seconds
    pub argon2_params: SerializableArgon2Params,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedPayload {
    pub signature: Vec<u8>,
    pub signing_public_key: [u8; 32],       // Sender's permanent verifying key
    pub permanent_dh_public_key: [u8; 32],  // Sender's permanent DH public key
    pub compressed_message: Vec<u8>,
}


impl Packet {
    pub fn new(
        ephemeral_dh_public_key: [u8; 32],
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
        pow_nonce: u64,
        pow_hash: Vec<u8>,
        pow_difficulty: usize,
        recipient_address: Address, // Added recipient_address
        timestamp: u64,
        ttl: u64,
        argon2_params: SerializableArgon2Params,
    ) -> Self {
        Packet {
            ephemeral_dh_public_key,
            nonce,
            ciphertext,
            pow_nonce,
            pow_hash,
            pow_difficulty,
            recipient_address, // Added recipient_address
            timestamp,
            ttl,
            argon2_params,
        }
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
        recipient_public_dh_key: &X25519PublicKey, // Recipient's permanent DH public key
        recipient_address: Address,
        message: &[u8],
        pow_difficulty: usize,
        ttl: u64,
        argon2_params: SerializableArgon2Params,
    ) -> Self {
        info!("Creating signed and encrypted packet");

        // Compress the message
        let compression_level = 0; // Adjust as needed
        let compressed_message =
            encode_all(&message[..], compression_level).expect("Failed to compress message");

        // Sign the compressed message
        let signature = auth
            .sign_message(&compressed_message)
            .to_bytes()
            .to_vec();

        // Create EncryptedPayload
        let encrypted_payload = EncryptedPayload {
            signature,
            signing_public_key: auth.verifying_key().to_bytes(),
            permanent_dh_public_key: *encryption.permanent_public_key.as_bytes(),
            compressed_message,
        };

        // Serialize EncryptedPayload
        let encrypted_payload_bytes = bincode::serialize(&encrypted_payload)
            .expect("Failed to serialize EncryptedPayload");

        // Encrypt the serialized EncryptedPayload using ephemeral keys
        let (ciphertext, nonce, ephemeral_dh_public_key_bytes) = encryption.encrypt_message(
            recipient_public_dh_key,
            &encrypted_payload_bytes,
        );

        // Prepare the Packet data
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut packet = Packet {
            ephemeral_dh_public_key: ephemeral_dh_public_key_bytes,
            nonce,
            ciphertext,
            pow_nonce: 0,
            pow_hash: Vec::new(),
            pow_difficulty,
            recipient_address,
            timestamp,
            ttl,
            argon2_params: argon2_params.clone(),
        };

        // Perform PoW
        let packet_data = packet.serialize();
        let argon2_params_native = argon2_params.to_argon2_params();
        let pow = PoW::new(
            &packet_data,
            pow_difficulty,
            PoWAlgorithm::Argon2id(argon2_params_native),
        )
        .unwrap();

        let (pow_hash, pow_nonce) = pow.calculate_pow();

        // Update Packet with PoW results
        packet.pow_nonce = pow_nonce;
        packet.pow_hash = pow_hash;

        packet
    }

    pub fn verify_and_decrypt(
        &self,
        encryption: &Encryption,
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
        let sender_ephemeral_public_key = X25519PublicKey::from(self.ephemeral_dh_public_key);
        let decrypted_payload_bytes = encryption.decrypt_message(
            &sender_ephemeral_public_key,
            &self.nonce,
            &self.ciphertext,
        );

        // Step 3: Deserialize EncryptedPayload
        let encrypted_payload: EncryptedPayload =
            bincode::deserialize(&decrypted_payload_bytes).ok()?;

        // Step 4: Verify the signature over the compressed message
        let verifying_key =
            VerifyingKey::from_bytes(&encrypted_payload.signing_public_key).ok()?;
        let signature_bytes: &[u8; 64] = encrypted_payload.signature.as_slice().try_into().ok()?;
        let signature = Signature::from_bytes(signature_bytes);

        if !Authentication::verify_message_with_key(
            &encrypted_payload.compressed_message,
            &signature,
            &verifying_key,
        ) {
            return None;
        }

        // Step 5: Decompress the message
        let decompressed_message = decode_all(&encrypted_payload.compressed_message[..]).ok()?;

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
