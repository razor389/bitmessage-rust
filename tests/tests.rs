// tests/tests.rs

#[cfg(test)]
mod tests {
    use bitmessage_rust::authentication::Authentication;
    use bitmessage_rust::encryption::Encryption;
    use bitmessage_rust::packet::Packet;
    use bitmessage_rust::pow::{PoW, PoWAlgorithm};
    use bitmessage_rust::serializable_argon2_params::SerializableArgon2Params; // Import the SerializableArgon2Params
    use argon2::Params as Argon2Params;
    use env_logger;
    #[allow(unused_imports)]
    use log::{info, debug, warn, error};

    #[test]
    fn test_encryption_decryption() {
        let encryption_a = Encryption::new();
        let encryption_b = Encryption::new();

        let message = b"Hello, world!";
        let (ciphertext, nonce) =
            encryption_a.encrypt_message(&encryption_b.our_public_key, message);

        let plaintext =
            encryption_b.decrypt_message(&encryption_a.our_public_key, &nonce, &ciphertext);
        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_signing_verification() {
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

    #[test]
    fn test_signed_encrypted_message() {
        use sha2::{Digest, Sha256};
        use x25519_dalek::PublicKey as X25519PublicKey;
        use bitmessage_rust::packet::ADDRESS_LENGTH;

        let auth_sender = Authentication::new();
        let enc_sender = Encryption::new();
        let auth_receiver = Authentication::new();
        let enc_receiver = Encryption::new();

        let message = b"Confidential message";

        let pow_difficulty = 1; // Adjust difficulty for testing purposes

        // Compute the recipient's address
        let recipient_address = {
            let mut hasher = Sha256::new();
            hasher.update(&auth_receiver.verifying_key().to_bytes());
            hasher.update(enc_receiver.our_public_key.as_bytes());
            let result = hasher.finalize();
            let mut address = [0u8; ADDRESS_LENGTH];
            address.copy_from_slice(&result[..ADDRESS_LENGTH]);
            address
        };

        let ttl = 60; // Arbitrary TTL for testing

        // Define Argon2id parameters
        let argon2_params = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params = SerializableArgon2Params::from_argon2_params(&argon2_params);

        // Sender creates a packet to send to the receiver
        let packet = Packet::create_signed_encrypted(
            &auth_sender,
            &enc_sender,
            &enc_receiver.our_public_key,
            recipient_address, // Include recipient address
            message,
            pow_difficulty,
            ttl,
            serializable_params.clone(), // Pass the SerializableArgon2Params
        );

        // Receiver verifies and decrypts the packet
        let decrypted_message = packet.verify_and_decrypt(
            &enc_receiver,
            &X25519PublicKey::from(packet.dh_public_key),
            pow_difficulty,
        );

        assert_eq!(decrypted_message.as_deref(), Some(message.as_ref()));
    }

    #[test]
    fn test_pow_algorithm_argon2id() {
        let data = b"hello world";
        let nonce = 12345u64;
        let params = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let expected_hash = PoWAlgorithm::calculate_argon2id(data, nonce, &params);

        let hash = PoWAlgorithm::calculate_argon2id(data, nonce, &params);

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_pow_verify_pow() {
        let data = "hello world";
        let difficulty = 1;
        let algorithm = PoWAlgorithm::Argon2id(Argon2Params::new(512, 1, 8, Some(32)).unwrap());
        let pow = PoW::new(data, difficulty, algorithm).unwrap();

        let (hash, nonce) = pow.calculate_pow();

        assert!(pow.verify_pow(&hash, nonce));
    }

    #[test]
    fn test_client_node_communication() {
        use std::sync::Arc;
        use bitmessage_rust::authentication::Authentication;
        use bitmessage_rust::client::Client;
        use bitmessage_rust::encryption::Encryption;
        use bitmessage_rust::node::Node;
        use env_logger;

        // Initialize the logger
        let _ = env_logger::builder().is_test(true).try_init();

        // Initialize clients' authentication and encryption
        let auth_a = Authentication::new();
        let enc_a = Encryption::new();

        let auth_b = Authentication::new();
        let enc_b = Encryption::new();

        // Define Argon2id parameters
        let argon2_params = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params = SerializableArgon2Params::from_argon2_params(&argon2_params);

        // Define node's minimum acceptable parameters
        let min_argon2_params = serializable_params.clone();

        // Create dummy node to compute clients' addresses
        let dummy_node = Arc::new(Node::new(
            0,
            vec![],
            1,
            3600,
            min_argon2_params.clone(),
        )); // Max TTL of 1 hour

        // Create clients connected to the dummy node
        let client_a = Client::new(auth_a, enc_a, Arc::clone(&dummy_node));
        let client_b = Client::new(auth_b, enc_b, Arc::clone(&dummy_node));

        // Compute node prefixes based on clients' addresses
        let prefix_length = 1; // Adjust as needed for testing
        let node_a_prefix = client_a.address[..prefix_length].to_vec();
        let node_b_prefix = client_b.address[..prefix_length].to_vec();

        let pow_difficulty = 1; // Adjust for testing purposes

        // Create nodes with unique IDs and PoW difficulty, using prefixes derived from clients' addresses
        let node_a = Arc::new(Node::new(
            1,
            node_a_prefix.clone(),
            pow_difficulty,
            3600,
            min_argon2_params.clone(),
        )); // Max TTL of 1 hour
        let node_b = Arc::new(Node::new(
            2,
            node_b_prefix.clone(),
            pow_difficulty,
            3600,
            min_argon2_params.clone(),
        )); // Max TTL of 1 hour

        // Connect nodes to each other
        node_a.connect(Arc::clone(&node_b));
        node_b.connect(Arc::clone(&node_a));

        // Update clients to connect to their respective nodes
        let client_a = Client::new(client_a.auth, client_a.encryption, Arc::clone(&node_a));
        let client_b = Client::new(client_b.auth, client_b.encryption, Arc::clone(&node_b));

        // Client A sends a message to Client B
        let message = b"Hello, Client B!";

        let ttl = 3600; // TTL of 1 hour

        client_a.send_message(
            &client_b.auth.verifying_key(),       // Recipient's verifying key
            &client_b.encryption.our_public_key,  // Recipient's DH public key
            message,
            pow_difficulty,
            ttl,                      // Include ttl
            serializable_params.clone(), // Pass the SerializableArgon2Params
        );

        // Client B retrieves messages (all messages from its node)
        let received_messages = client_b.receive_messages(pow_difficulty);

        // Verify that Client B received and decrypted the message from Client A
        assert_eq!(received_messages.len(), 1);
        assert_eq!(received_messages[0].as_slice(), message);
    }
}
