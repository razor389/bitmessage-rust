// tests/tests.rs

#[cfg(test)]
mod tests {
    use bitmessage_rust::authentication::Authentication;
    use bitmessage_rust::encryption::Encryption;
    use bitmessage_rust::packet::{Packet, ADDRESS_LENGTH};
    use bitmessage_rust::pow::{PoW, PoWAlgorithm};
    use bitmessage_rust::serializable_argon2_params::SerializableArgon2Params;
    use argon2::Params as Argon2Params;
    use env_logger;
    #[allow(unused_imports)]
    use log::{info, debug, warn, error};
    use sha2::{Digest, Sha256};
    use x25519_dalek::PublicKey as X25519PublicKey;
    use std::net::SocketAddr;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_encryption_decryption() {
        let encryption_a = Encryption::new();
        let encryption_b = Encryption::new();

        let message = b"Hello, world!";
        let (ciphertext, nonce) =
            encryption_a.encrypt_message(&encryption_b.our_public_key, message);

        let plaintext =
            encryption_b.decrypt_message(&encryption_a.our_public_key, &nonce, &ciphertext);
        assert_eq!(plaintext, message);
    }

    #[tokio::test]
    async fn test_signing_verification() {
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
        let data = b"hello world";
        let difficulty = 1;
        let algorithm = PoWAlgorithm::Argon2id(Argon2Params::new(512, 1, 8, Some(32)).unwrap());
        let pow = PoW::new(data, difficulty, algorithm).unwrap();

        let (hash, nonce) = pow.calculate_pow();

        assert!(pow.verify_pow(&hash, nonce));
    }

    #[tokio::test]
    async fn test_client_node_communication() {
        use bitmessage_rust::client::Client;
        use bitmessage_rust::node::Node;

        // Initialize the logger
        let _ = env_logger::builder().is_test(true).try_init();

        // Initialize clients' authentication and encryption
        let auth_a = Authentication::new();
        let enc_a = Encryption::new();

        let auth_b = Authentication::new();
        let enc_b = Encryption::new();

        // Extract public keys before moving into clients
        let auth_b_verifying_key = auth_b.verifying_key();
        let enc_b_public_key = enc_b.our_public_key;

        // Define Argon2id parameters
        let argon2_params = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params = SerializableArgon2Params::from_argon2_params(&argon2_params);

        // Define node's minimum acceptable parameters
        let min_argon2_params = serializable_params.clone();

        // Set up addresses for nodes (use loopback addresses with different ports)
        let address_a: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        let address_b: SocketAddr = "127.0.0.1:6001".parse().unwrap();

        // Create nodes with unique IDs and PoW difficulty
        let node_a = Node::new(
            1,
            vec![],
            1,
            3600,
            min_argon2_params.clone(),
            address_a,
        ).await;

        let node_b = Node::new(
            2,
            vec![],
            1,
            3600,
            min_argon2_params.clone(),
            address_b,
        ).await;

        // Start nodes
        node_a.start_gossip();
        node_b.start_gossip();

        // Node A connects to Node B
        node_a.connect_sender.send(address_b).await.unwrap();

        // Node B connects to Node A
        node_b.connect_sender.send(address_a).await.unwrap();

        // Spawn tasks to run the nodes
        let node_a_clone = Arc::clone(&node_a);
        tokio::spawn(async move {
            if let Err(e) = node_a_clone.run().await {
                error!("Node A failed: {:?}", e);
            }
        });

        let node_b_clone = Arc::clone(&node_b);
        tokio::spawn(async move {
            if let Err(e) = node_b_clone.run().await {
                error!("Node B failed: {:?}", e);
            }
        });

        // Allow some time for nodes to start and connect
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Create clients connected to their respective nodes
        let client_a = Client::new(auth_a, enc_a, address_a);
        let client_b = Client::new(auth_b, enc_b, address_b);

        // Client A sends a message to Client B
        let message = b"Hello, Client B!";

        let ttl = 3600; // TTL of 1 hour

        client_a.send_message(
            &auth_b_verifying_key,    // Recipient's verifying key
            &enc_b_public_key,        // Recipient's DH public key
            message,
            1,                             // PoW difficulty
            ttl,                           // Include ttl
            serializable_params.clone(),   // Pass the SerializableArgon2Params
        ).await;

        // Allow some time for the message to propagate
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Client B retrieves messages
        let received_messages = client_b.receive_messages(1).await;

        // Verify that Client B received and decrypted the message from Client A
        assert_eq!(received_messages.len(), 1);
        assert_eq!(received_messages[0].as_slice(), message);
    }
}
