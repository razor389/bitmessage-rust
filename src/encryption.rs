// src/encryption.rs
use x25519_dalek::{PublicKey as X25519PublicKey, X25519_BASEPOINT_BYTES, x25519};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::rngs::OsRng;
use rand::RngCore;

pub struct Encryption {
    pub our_public_key: X25519PublicKey,
    pub our_private_key: [u8; 32],
}

impl Encryption {
    pub fn new() -> Encryption {
        let mut csprng = OsRng;
        let mut our_private_key = [0u8; 32];
        csprng.fill_bytes(&mut our_private_key);
        let our_public_key_bytes = x25519(our_private_key, X25519_BASEPOINT_BYTES);
        let our_public_key = X25519PublicKey::from(our_public_key_bytes);
        Encryption {
            our_public_key,
            our_private_key,
        }
    }

    pub fn encrypt_message(&self, recipient_public_key: &X25519PublicKey, message: &[u8]) -> (Vec<u8>, [u8; 12]) {
        let shared_secret = x25519(self.our_private_key, *recipient_public_key.as_bytes());

        let key = Key::<Aes256Gcm>::from_slice(&shared_secret);
        let cipher = Aes256Gcm::new(key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, message).expect("Encryption failed");
        (ciphertext, nonce_bytes)
    }

    pub fn decrypt_message(&self, sender_public_key: &X25519PublicKey, nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        let shared_secret = x25519(self.our_private_key, *sender_public_key.as_bytes());

        let key = Key::<Aes256Gcm>::from_slice(&shared_secret);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        cipher.decrypt(nonce, ciphertext).expect("Decryption failed")
    }
}
