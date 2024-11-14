// tests/tests.rs

#[cfg(test)]
mod tests {
    use shadow_link::authentication::Authentication;
    use shadow_link::client::Client;
    use shadow_link::common::NodeInfo;
    use shadow_link::encryption::Encryption;
    use shadow_link::node::Node;
    use shadow_link::packet::{Packet, ADDRESS_LENGTH};
    use shadow_link::pow::{PoW, PoWAlgorithm};
    use shadow_link::serializable_argon2_params::SerializableArgon2Params;
    use argon2::Params as Argon2Params;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use env_logger;
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};
    use x25519_dalek::PublicKey as X25519PublicKey;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    /// Helper function to initialize the logger once for all tests.
    /// This avoids multiple initializations that can cause warnings.
    fn init_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    /// Helper function to generate a recipient address based on verifying key and encryption public key.
    fn generate_recipient_address(verifying_key: &VerifyingKey, encryption_pub: &X25519PublicKey) -> [u8; ADDRESS_LENGTH] {
        let mut hasher = Sha256::new();
        hasher.update(verifying_key.to_bytes());
        hasher.update(encryption_pub.as_bytes());
        let result = hasher.finalize();
        let mut address = [0u8; ADDRESS_LENGTH];
        address.copy_from_slice(&result[..ADDRESS_LENGTH]);
        address
    }

    /// Helper function to create a node and return its Arc<Node>
    async fn create_node(
        address: SocketAddr,
        prefix_length: usize,
        pow_difficulty: usize,
        max_ttl: u64,
        min_argon2_params: SerializableArgon2Params,
        cleanup_interval: Duration, // New parameter
        blacklist_duration: Duration,
    ) -> Arc<Node> {
        // Generate signing and verifying keys
        let mut csprng = OsRng {};
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();

        // Create the node with configurable blacklist_duration
        let node = Node::new(
            &public_key_bytes,
            address,
            prefix_length,
            pow_difficulty,
            max_ttl,
            min_argon2_params,
            cleanup_interval, 
            blacklist_duration,
        )
        .await;

        node
    }

    /// Helper function to wait for a short duration to allow asynchronous tasks to complete
    async fn wait_short() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_encryption_decryption() {
        init_logger();

        let encryption_a = Encryption::new();
        let encryption_b = Encryption::new();

        let message = b"Hello, world!";

        // Encryption A encrypts a message to Encryption B
        let (ciphertext, nonce, ephemeral_public_key_bytes) =
            encryption_a.encrypt_message(&encryption_b.permanent_public_key, message);

        // Convert ephemeral public key bytes to X25519PublicKey
        let ephemeral_public_key = X25519PublicKey::from(ephemeral_public_key_bytes);

        // Encryption B decrypts the message using the sender's ephemeral public key
        let plaintext = encryption_b.decrypt_message(
            &ephemeral_public_key,
            &nonce,
            &ciphertext,
        );
        assert_eq!(plaintext, message);
    }


    #[tokio::test]
    async fn test_signing_verification() {
        init_logger();

        let auth_a = Authentication::new();
        let auth_b = Authentication::new();

        let message = b"Authenticate me!";
        let signature = auth_a.sign_message(message);

        let sender_public_key = auth_a.verifying_key();

        // Verify with the correct public key and message
        assert!(Authentication::verify_message_with_key(
            message,
            &signature,
            &sender_public_key
        ));

        // Verify fails with an incorrect public key
        let wrong_sender_public_key = auth_b.verifying_key();
        assert!(!Authentication::verify_message_with_key(
            message,
            &signature,
            &wrong_sender_public_key
        ));
    }

    #[tokio::test]
    async fn test_signed_encrypted_message() {
        init_logger();

        let auth_sender = Authentication::new();
        let enc_sender = Encryption::new();
        let auth_receiver = Authentication::new();
        let enc_receiver = Encryption::new();

        let message = b"Confidential message";

        let pow_difficulty = 1; // Adjust difficulty for testing purposes

        // Compute the recipient's address
        let recipient_address = generate_recipient_address(&auth_receiver.verifying_key(), &enc_receiver.permanent_public_key);

        let ttl = 60; // Arbitrary TTL for testing

        // Define Argon2id parameters
        let argon2_params = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params = SerializableArgon2Params::from_argon2_params(&argon2_params);

        // Sender creates a packet to send to the receiver
        let packet = Packet::create_signed_encrypted(
            &auth_sender,
            &enc_sender,
            &enc_receiver.permanent_public_key,
            recipient_address, // Include recipient address
            message,
            pow_difficulty,
            ttl,
            serializable_params.clone(), // Pass the SerializableArgon2Params
        );

        // Receiver verifies and decrypts the packet
        let decrypted_message = packet.verify_and_decrypt(
            &enc_receiver,
            pow_difficulty,
        );

        assert_eq!(decrypted_message.as_deref(), Some(message.as_ref()));
    }

    #[test]
    fn test_pow_algorithm_argon2id() {
        let data = b"hello world";
        let nonce = 12345u64;
        let params = Argon2Params::new(512, 1, 8, Some(32)).unwrap();
        let expected_hash = PoWAlgorithm::calculate_argon2id(data, nonce, &params);

        let hash = PoWAlgorithm::calculate_argon2id(data, nonce, &params);

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_pow_verify_pow() {
        let data = b"hello world";
        let difficulty = 1;
        let algorithm = PoWAlgorithm::Argon2id(Argon2Params::new(512, 1, 8, Some(32)).unwrap());
        let pow = PoW::new(data, difficulty, algorithm).unwrap();

        let (hash, nonce) = pow.calculate_pow();

        assert!(pow.verify_pow(&hash, nonce));
    }


    

}
