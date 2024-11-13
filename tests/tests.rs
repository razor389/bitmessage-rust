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


    /// Test client-node connection and subscription
    #[tokio::test]
    async fn test_client_node_connection() {
        init_logger();

        // Initialize node parameters with prefix_length = 0 and short blacklist_duration
        let address: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let prefix_length = 0; // Store all packets
        let pow_difficulty = 1000;
        let max_ttl = 60; // 1 minute
        let min_argon2_params = SerializableArgon2Params {
            m_cost: 4096,
            t_cost: 3,
            p_cost: 1,
            output_length: Some(32),
        };
        let cleanup_interval = Duration::from_secs(5); // Short duration for testing
        let blacklist_duration = Duration::from_secs(15);
        // Create node
        let _node = create_node(address, prefix_length, pow_difficulty, max_ttl, min_argon2_params, cleanup_interval, blacklist_duration).await;

        // Create client
        let auth = Authentication::new();
        let encryption = Encryption::new();
        let client = Client::new(auth, encryption, address);
        let client = Arc::new(client);

        // Allow some time for the node to start listening
        wait_short().await;

        // Subscribe to node, clone the Arc to pass to the subscription task
        let client_sub = client.clone();
        let subscribe_handle = tokio::spawn(async move {
            client_sub.subscribe_and_receive_messages(pow_difficulty).await;
        });

        // Allow subscription to process
        wait_short().await;

        // Since we haven't sent any messages yet, the subscriber should receive no messages
        // You can enhance this by capturing logs or adding additional instrumentation
        // For now, we'll just ensure that the subscription doesn't panic

        // Clean up: cancel the subscription task
        subscribe_handle.abort();
    }

    /// Test message forwarding between nodes
    #[tokio::test]
    async fn test_message_forwarding() {
        init_logger();

        // Initialize node A with prefix_length = 16 and short blacklist_duration
        let address_a: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let prefix_length_a = 16; // Store only packets matching the first 16 bits
        let pow_difficulty_a = 1;
        let max_ttl_a = 120; // 2 minutes
        let min_argon2_params_a = SerializableArgon2Params {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            output_length: Some(32),
        };
        let cleanup_interval_a = Duration::from_secs(5); // Short interval for testing
        let blacklist_duration_a = Duration::from_secs(5); // Short blacklist duration for testing
        let node_a = create_node(
            address_a,
            prefix_length_a,
            pow_difficulty_a,
            max_ttl_a,
            min_argon2_params_a,
            cleanup_interval_a,
            blacklist_duration_a,
        )
        .await;

        // Initialize node B with prefix_length = 0 and short blacklist_duration
        let address_b: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        let prefix_length_b = 0; // Store all packets
        let pow_difficulty_b = 1;
        let max_ttl_b = 120; // 2 minutes
        let min_argon2_params_b = SerializableArgon2Params {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            output_length: Some(32),
        };
        let cleanup_interval_b = Duration::from_secs(5); // Short interval for testing
        let blacklist_duration_b = Duration::from_secs(5); // Short blacklist duration for testing
        let node_b = create_node(
            address_b,
            prefix_length_b,
            pow_difficulty_b,
            max_ttl_b,
            min_argon2_params_b,
            cleanup_interval_b,
            blacklist_duration_b,
        )
        .await;

        // Allow nodes to start
        wait_short().await;

        // Connect node A to node B
        node_a
            .update_routing_table(NodeInfo {
                id: node_b.id,
                address: address_b,
            })
            .await;

        // Create client connected to node A
        let auth = Authentication::new();
        let encryption = Encryption::new();
        let client = Client::new(auth, encryption, address_a);
        let client = Arc::new(client);

        // Allow some time for the routing table update
        wait_short().await;

        // Create a message to send from client to node B via node A
        let message = b"Forward this message to node B";
        let _recipient_address = generate_recipient_address(&client.auth.verifying_key(), &client.encryption.permanent_public_key);

        let pow_difficulty = pow_difficulty_a;
        let ttl = 60; // 1 minute

        // Define Argon2id parameters
        let argon2_params = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params = SerializableArgon2Params::from_argon2_params(&argon2_params);

        // Create a subscription client to node B
        let auth_sub = Authentication::new();
        let encryption_sub = Encryption::new();
        let client_sub = Client::new(auth_sub, encryption_sub, address_b);
        let client_sub = Arc::new(client_sub);

        // Spawn the subscription client
        let client_sub_clone = client_sub.clone();
        let subscribe_handle = tokio::spawn(async move {
            client_sub_clone.subscribe_and_receive_messages(pow_difficulty_b).await;
        });

        // Send message from client to node A
        client
            .send_message(
                &client_sub.auth.verifying_key(),

                &client_sub.encryption.permanent_public_key,
                message,
                pow_difficulty,
                ttl,
                serializable_params.clone(),
            )
            .await;

        // Allow time for message forwarding
        tokio::time::sleep(Duration::from_millis(500)).await; // Increased wait time

        // Receive the packet via client_sub
        if let Some(received_packet) = client_sub.receive_packet().await {
            // Decrypt the packet
            let decrypted_message = received_packet
                .verify_and_decrypt(&client_sub.encryption, pow_difficulty_b)
                .expect("Failed to decrypt received packet");

            // Compare decrypted message with original message
            assert_eq!(
                decrypted_message.as_slice(),
                message,
                "Decrypted message does not match original message"
            );
        } else {
            panic!("Did not receive forwarded packet on Node B");
        }

        // Clean up: cancel the subscription task
        subscribe_handle.abort();
    }

    /// Test TTL message expiration
    #[tokio::test]
    async fn test_ttl_message_expiration() {
        init_logger();

        // Initialize node with prefix_length = 0 and short blacklist_duration
        let address: SocketAddr = "127.0.0.1:9003".parse().unwrap();
        let prefix_length = 0; // Store all packets
        let pow_difficulty = 1;
        let max_ttl = 5; // 5 seconds for quick testing
        let min_argon2_params = SerializableArgon2Params {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            output_length: Some(32),
        };
        let cleanup_interval =Duration::from_secs(5); // Short duration for testing
        let blacklist_duration = Duration::from_secs(5); // Short duration for testing
        let node = create_node(address, prefix_length, pow_difficulty, max_ttl, min_argon2_params, cleanup_interval,blacklist_duration).await;

        // Create client
        let auth = Authentication::new();
        let encryption = Encryption::new();
        let client = Client::new(auth, encryption, address);
        let client = Arc::new(client);

        // Allow node to start
        wait_short().await;

        // Subscribe to node
        let client_sub = client.clone();
        let client_sub_verifying_key = &client_sub.auth.verifying_key().clone();
        let client_sub_pub_key = &client_sub.encryption.permanent_public_key.clone();
        let subscribe_handle = tokio::spawn(async move {
            client_sub.subscribe_and_receive_messages(pow_difficulty).await;
        });

        // Allow subscription to process
        wait_short().await;

        // Create a message
        let message = b"This message will expire";
        let _recipient_address = generate_recipient_address(&client.auth.verifying_key(), &client.encryption.permanent_public_key);

        let ttl = 5; // 5 seconds

        // Define Argon2id parameters
        let argon2_params = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params = SerializableArgon2Params::from_argon2_params(&argon2_params);

        // Send message
        client
            .send_message(
                client_sub_verifying_key,
                client_sub_pub_key,
                message,
                pow_difficulty,
                ttl,
                serializable_params.clone(),
            )
            .await;

        // Allow time for message to be processed
        wait_short().await;

        // Verify message is stored
        {
            let store = node.packet_store.lock().await;
            assert_eq!(store.len(), 1);
        }

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_secs(6)).await;

        // Allow cleanup task to run
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Verify that the packet has been removed
        {
            let store = node.packet_store.lock().await;
            assert_eq!(store.len(), 0);
        }

        // Clean up: cancel the subscription task
        subscribe_handle.abort();
    }

    /// Test Argon2 and TTL validation
    #[tokio::test]
    async fn test_argon2_and_ttl_validation() {
        init_logger();

        // Initialize node with prefix_length = 0 and short blacklist_duration
        let address: SocketAddr = "127.0.0.1:9004".parse().unwrap();
        let prefix_length = 0; // Store all packets
        let pow_difficulty = 1;
        let max_ttl = 60; // 1 minute
        let min_argon2_params = SerializableArgon2Params {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            output_length: Some(32),
        };
        let cleanup_interval = Duration::from_secs(5);
        let blacklist_duration = Duration::from_secs(5); // Short duration for testing
        let node = create_node(address, prefix_length, pow_difficulty, max_ttl, min_argon2_params.clone(), cleanup_interval, blacklist_duration).await;

        // Create client
        let auth = Authentication::new();
        let encryption = Encryption::new();
        let client = Client::new(auth, encryption, address);
        let client = Arc::new(client);

        // Allow node to start
        wait_short().await;

        // Subscribe to node
        let client_sub = client.clone();
        let subscribe_handle = tokio::spawn(async move {
            client_sub.subscribe_and_receive_messages(pow_difficulty).await;
        });

        // Allow subscription to process
        wait_short().await;

        // Case 1: Valid packet
        let message_valid = b"Valid packet message";
        let _recipient_address_valid = generate_recipient_address(&client.auth.verifying_key(), &client.encryption.permanent_public_key);

        let pow_difficulty_valid = pow_difficulty;
        let ttl_valid = 60; // Within max_ttl

        let argon2_params_valid = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params_valid = SerializableArgon2Params::from_argon2_params(&argon2_params_valid);

        client
            .send_message(
                &client.auth.verifying_key(),
                &client.encryption.permanent_public_key,
                message_valid,
                pow_difficulty_valid,
                ttl_valid,
                serializable_params_valid.clone(),
            )
            .await;

        // Allow time for message to be processed
        wait_short().await;

        // Verify packet is stored
        {
            let store = node.packet_store.lock().await;
            assert_eq!(store.len(), 1);
        }

        // Case 2: Packet with ttl exceeding max_ttl
        let message_invalid_ttl = b"Invalid TTL packet";
        let _recipient_address_invalid_ttl = generate_recipient_address(&client.auth.verifying_key(), &client.encryption.permanent_public_key);

        let pow_difficulty_invalid_ttl = pow_difficulty;
        let ttl_invalid = max_ttl + 10; // Exceeds max_ttl

        let argon2_params_invalid_ttl = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params_invalid_ttl = SerializableArgon2Params::from_argon2_params(&argon2_params_invalid_ttl);

        client
            .send_message(
                &client.auth.verifying_key(),
                &client.encryption.permanent_public_key,
                message_invalid_ttl,
                pow_difficulty_invalid_ttl,
                ttl_invalid,
                serializable_params_invalid_ttl.clone(),
            )
            .await;

        // Allow time for message to be processed
        wait_short().await;

        // Verify packet is not stored and sender is blacklisted
        {
            let store = node.packet_store.lock().await;
            assert_eq!(store.len(), 1); // Only the valid packet is stored

            let blacklist = node.blacklist.lock().await;
            assert!(blacklist.contains_key(&address.ip()));
        }

        // Case 3: Packet with insufficient Argon2 parameters
        let message_invalid_argon2 = b"Invalid Argon2 parameters";
        let _recipient_address_invalid_argon2 = generate_recipient_address(&client.auth.verifying_key(), &client.encryption.permanent_public_key);

        let pow_difficulty_invalid_argon2 = pow_difficulty;
        let ttl_invalid_argon2 = 60; // Within max_ttl

        let argon2_params_invalid = Argon2Params::new(512, 1, 1, Some(16)).unwrap(); // Below min_argon2_params
        let serializable_params_invalid = SerializableArgon2Params::from_argon2_params(&argon2_params_invalid);

        client
            .send_message(
                &client.auth.verifying_key(),
                &client.encryption.permanent_public_key,
                message_invalid_argon2,
                pow_difficulty_invalid_argon2,
                ttl_invalid_argon2,
                serializable_params_invalid.clone(),
            )
            .await;

        // Allow time for message to be processed
        wait_short().await;

        // Verify packet is not stored and sender is blacklisted
        {
            let store = node.packet_store.lock().await;
            assert_eq!(store.len(), 1); // Only the valid packet is stored

            let blacklist = node.blacklist.lock().await;
            assert!(blacklist.contains_key(&address.ip()));
        }

        // Clean up: cancel the subscription task
        subscribe_handle.abort();
    }

    /// Test blacklisting functionality
    #[tokio::test]
    async fn test_blacklisting() {
        init_logger();

        // Initialize node with prefix_length = 0 and short blacklist_duration
        let address: SocketAddr = "127.0.0.1:9005".parse().unwrap();
        let prefix_length = 0; // Store all packets
        let pow_difficulty = 1;
        let max_ttl = 60; // 1 minute
        let min_argon2_params = SerializableArgon2Params {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            output_length: Some(32),
        };
        let cleanup_interval = Duration::from_secs(60);
        let blacklist_duration = Duration::from_secs(5); // Short duration for testing
        let node = create_node(address, prefix_length, pow_difficulty, max_ttl, min_argon2_params.clone(), cleanup_interval,blacklist_duration).await;

        // Create client
        let auth = Authentication::new();
        let encryption = Encryption::new();
        let client = Client::new(auth, encryption, address);
        let client = Arc::new(client);

        // Allow node to start
        wait_short().await;

        // Subscribe to node
        let client_sub = client.clone();
        let client_sub_ver_key = &client_sub.auth.verifying_key().clone();
        let client_sub_pub_key = &client_sub.encryption.permanent_public_key.clone();
        let subscribe_handle = tokio::spawn(async move {
            client_sub.subscribe_and_receive_messages(pow_difficulty).await;
        });

        // Allow subscription to process
        wait_short().await;

        // Attempt to send an invalid packet (exceeds TTL)
        let message_invalid_ttl = b"Invalid TTL packet for blacklisting test";
        let _recipient_address_invalid_ttl = generate_recipient_address(&client.auth.verifying_key(), &client.encryption.permanent_public_key);

        let pow_difficulty_invalid_ttl = pow_difficulty;
        let ttl_invalid = max_ttl + 10; // Exceeds max_ttl

        let argon2_params_invalid_ttl = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params_invalid_ttl = SerializableArgon2Params::from_argon2_params(&argon2_params_invalid_ttl);

        client
            .send_message(
                client_sub_ver_key,
                client_sub_pub_key,
                message_invalid_ttl,
                pow_difficulty_invalid_ttl,
                ttl_invalid,
                serializable_params_invalid_ttl.clone(),
            )
            .await;

        // Allow time for message to be processed and blacklisting
        wait_short().await;

        // Verify that the sender is blacklisted
        {
            let blacklist = node.blacklist.lock().await;
            assert!(blacklist.contains_key(&address.ip()));
        }

        // Attempt to send another valid packet from the same client, which should be rejected due to blacklisting
        let message_valid = b"Valid message after blacklisting";
        let _recipient_address_valid = generate_recipient_address(&client.auth.verifying_key(), &client.encryption.permanent_public_key);

        let pow_difficulty_valid = pow_difficulty;
        let ttl_valid = 60; // Within max_ttl

        let argon2_params_valid = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params_valid = SerializableArgon2Params::from_argon2_params(&argon2_params_valid);

        client
            .send_message(
                client_sub_ver_key,
                client_sub_pub_key,
                message_valid,
                pow_difficulty_valid,
                ttl_valid,
                serializable_params_valid.clone(),
            )
            .await;

        // Allow time for message to be processed
        wait_short().await;

        // Verify that the new packet is not stored
        {
            let store = node.packet_store.lock().await;
            assert_eq!(store.len(), 0); // No packets should be stored
        }

        // Clean up: cancel the subscription task
        subscribe_handle.abort();
    }

    /// Test blacklist expiration functionality
    #[tokio::test]
    async fn test_blacklist_expiration() {
        init_logger();

        // Initialize node with prefix_length = 0 and short blacklist_duration
        let address: SocketAddr = "127.0.0.1:9006".parse().unwrap();
        let prefix_length = 0; // Store all packets
        let pow_difficulty = 1;
        let max_ttl = 60; // 1 minute
        let min_argon2_params = SerializableArgon2Params {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            output_length: Some(32),
        };
        let cleanup_interval = Duration::from_secs(5);
        let blacklist_duration = Duration::from_secs(5); // Short duration for testing
        let node = create_node(address, prefix_length, pow_difficulty, max_ttl, min_argon2_params.clone(), cleanup_interval, blacklist_duration).await;

        // Create client
        let auth = Authentication::new();
        let encryption = Encryption::new();
        let client = Client::new(auth, encryption, address);
        let client = Arc::new(client);

        // Allow node to start
        wait_short().await;

        // Subscribe to node
        let client_sub = client.clone();
        let client_sub_ver_key = &client_sub.auth.verifying_key().clone();
        let client_sub_pub_key = &client_sub.encryption.permanent_public_key.clone();
        let subscribe_handle = tokio::spawn(async move {
            client_sub.subscribe_and_receive_messages(pow_difficulty).await;
        });

        // Allow subscription to process
        wait_short().await;

        // Send an invalid packet to blacklist the client
        let message_invalid_ttl = b"Invalid TTL packet for blacklist expiration test";
        let _recipient_address_invalid_ttl = generate_recipient_address(&client.auth.verifying_key(), &client.encryption.permanent_public_key);

        let pow_difficulty_invalid_ttl = pow_difficulty;
        let ttl_invalid = max_ttl + 10; // Exceeds max_ttl

        let argon2_params_invalid_ttl = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params_invalid_ttl = SerializableArgon2Params::from_argon2_params(&argon2_params_invalid_ttl);

        client
            .send_message(
                client_sub_ver_key,
                client_sub_pub_key,
                message_invalid_ttl,
                pow_difficulty_invalid_ttl,
                ttl_invalid,
                serializable_params_invalid_ttl.clone(),
            )
            .await;

        // Allow time for message to be processed and blacklisting
        wait_short().await;

        // Verify that the sender is blacklisted
        {
            let blacklist = node.blacklist.lock().await;
            assert!(blacklist.contains_key(&address.ip()));
        }

        // Wait for blacklist expiration (short duration for testing)
        tokio::time::sleep(Duration::from_secs(6)).await; // Wait a bit longer than the blacklist timeout

        // Verify that the blacklist entry has been removed
        {
            let blacklist = node.blacklist.lock().await;
            assert!(!blacklist.contains_key(&address.ip()));
        }

        // Send a valid packet again, which should now be accepted
        let message_valid = b"Valid message after blacklist expiration";
        let _recipient_address_valid = generate_recipient_address(&client.auth.verifying_key(), &client.encryption.permanent_public_key);

        let pow_difficulty_valid = pow_difficulty;
        let ttl_valid = 60; // Within max_ttl

        let argon2_params_valid = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params_valid = SerializableArgon2Params::from_argon2_params(&argon2_params_valid);

        client
            .send_message(
                client_sub_ver_key,
                client_sub_pub_key,
                message_valid,
                pow_difficulty_valid,
                ttl_valid,
                serializable_params_valid.clone(),
            )
            .await;

        // Allow time for message to be processed
        wait_short().await;

        // Verify that the new packet is stored
        {
            let store = node.packet_store.lock().await;
            assert_eq!(store.len(), 1);
        }

        // Clean up: cancel the subscription task
        subscribe_handle.abort();
    }

}
