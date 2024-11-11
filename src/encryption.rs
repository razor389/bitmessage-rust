// src/encryption.rs
use x25519_dalek::{PublicKey as X25519PublicKey, X25519_BASEPOINT_BYTES, x25519};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::rngs::OsRng;
use rand::RngCore;

pub struct Encryption {
    pub permanent_public_key: X25519PublicKey,
    permanent_private_key: [u8; 32],
}

impl Encryption {
    pub fn new() -> Encryption {
        let mut csprng = OsRng;
        let mut permanent_private_key = [0u8; 32];
        csprng.fill_bytes(&mut permanent_private_key);
        let permanent_public_key_bytes = x25519(permanent_private_key, X25519_BASEPOINT_BYTES);
        let permanent_public_key = X25519PublicKey::from(permanent_public_key_bytes);
        Encryption {
            permanent_public_key,
            permanent_private_key,
        }
    }

    pub fn encrypt_message(
        &self,
        recipient_public_key: &X25519PublicKey,
        message: &[u8],
    ) -> (Vec<u8>, [u8; 12], [u8; 32]) {
        // Generate a new ephemeral private key
        let mut csprng = OsRng;
        let mut ephemeral_private_key = [0u8; 32];
        csprng.fill_bytes(&mut ephemeral_private_key);
        let ephemeral_public_key_bytes = x25519(ephemeral_private_key, X25519_BASEPOINT_BYTES);
        let ephemeral_public_key = X25519PublicKey::from(ephemeral_public_key_bytes);

        // Compute shared secret
        let shared_secret = x25519(ephemeral_private_key, *recipient_public_key.as_bytes());

        // Use the shared secret as the key for encryption
        let key = Key::<Aes256Gcm>::from_slice(&shared_secret);
        let cipher = Aes256Gcm::new(key);

        let mut nonce_bytes = [0u8; 12];
        csprng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, message).expect("Encryption failed");
        (ciphertext, nonce_bytes, *ephemeral_public_key.as_bytes())
    }

    pub fn decrypt_message(
        &self,
        sender_ephemeral_public_key: &X25519PublicKey,
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Vec<u8> {
        // Compute shared secret
        let shared_secret = x25519(self.permanent_private_key, *sender_ephemeral_public_key.as_bytes());

        let key = Key::<Aes256Gcm>::from_slice(&shared_secret);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        cipher.decrypt(nonce, ciphertext).expect("Decryption failed")
    }
}
