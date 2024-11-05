// src/authentication.rs

use ed25519_dalek::{Signer, Verifier, VerifyingKey, SigningKey, Signature};
use rand::rngs::OsRng;

pub struct Authentication {
    pub signing_key: SigningKey,
}

impl Authentication {
    pub fn new() -> Authentication {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Authentication { signing_key }
    }

    pub fn sign_message(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn verify_message_with_key(
        message: &[u8],
        signature: &Signature,
        public_key: &VerifyingKey,
    ) -> bool {
        public_key.verify(message, signature).is_ok()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}
