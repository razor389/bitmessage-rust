// src/client.rs

use crate::packet::{Packet, Address, ADDRESS_LENGTH};
use crate::authentication::Authentication;
use crate::encryption::Encryption;
use crate::common::{Message, NodeInfoExtended};
use crate::serializable_argon2_params::SerializableArgon2Params;
use tokio::sync::{mpsc, Mutex};
use x25519_dalek::PublicKey as X25519PublicKey;
use ed25519_dalek::VerifyingKey;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use log::{info, warn, error};
use sha2::{Sha256, Digest};

pub struct Client {
    pub auth: Authentication,
    pub encryption: Encryption,
    pub address: Address,
    pub node_address: SocketAddr,
    pub incoming_tx: mpsc::Sender<Packet>, // Sender to send received packets
    pub incoming_rx: Mutex<mpsc::Receiver<Packet>>, // Receiver to receive packets
}

impl Client {
    pub fn new(
        auth: Authentication,
        encryption: Encryption,
        node_address: SocketAddr,
    ) -> Self {
        // Compute the client's address by hashing the public keys
        let mut hasher = Sha256::new();
        hasher.update(&auth.verifying_key().to_bytes());
        hasher.update(encryption.permanent_public_key.as_bytes());
        let result = hasher.finalize();
        let mut address = [0u8; ADDRESS_LENGTH];
        address.copy_from_slice(&result[..ADDRESS_LENGTH]);

        info!("Client created with address {:?}", hex::encode(address));
        let (tx, rx) = mpsc::channel(100);

        Client {
            auth,
            encryption,
            address,
            node_address,
            incoming_tx: tx,
            incoming_rx: Mutex::new(rx),
        }
    }

    /// Function to handle incoming packets and send them through the channel
    pub async fn handle_incoming_packet(&self, packet: Packet) {
        let _ = self.incoming_tx.send(packet).await;
    }

    /// Function to receive packets from the subscription channel
    pub async fn receive_packet(&self) -> Option<Packet> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await
    }

    /// Perform handshake with node
    pub async fn handshake_with_node(&self) -> Option<NodeInfoExtended> {
        match TcpStream::connect(self.node_address).await {
            Ok(mut stream) => {
                // Send ClientHandshake message
                let message = Message::ClientHandshake;
                let data = bincode::serialize(&message).expect("Failed to serialize message");
                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to send handshake: {:?}", e);
                }

                // Receive Node's handshake acknowledgment
                let mut buffer = vec![0u8; 4096];
                let n = stream.read(&mut buffer).await.expect("Failed to read handshake ack");
                let response: Message = bincode::deserialize(&buffer[..n]).expect("Failed to deserialize handshake ack");

                if let Message::ClientHandshakeAck(node_info) = response {
                    // Return node's info
                    return Some(node_info);
                } else {
                    warn!("Unexpected response during handshake");
                }
            }
            Err(e) => {
                error!("Failed to connect to node: {:?}", e);
            }
        }
        None
    }

    /// Send a message to a recipient
    pub async fn send_message(
        &self,
        recipient_verifying_key: &VerifyingKey,
        recipient_dh_public_key: &X25519PublicKey,
        message: &[u8],
        pow_difficulty: usize,
        ttl: u64,
        argon2_params: SerializableArgon2Params,
    ) {
        // Compute the recipient's address by hashing their public keys
        let recipient_address = {
            let mut hasher = Sha256::new();
            hasher.update(&recipient_verifying_key.to_bytes());
            hasher.update(recipient_dh_public_key.as_bytes());
            let result = hasher.finalize();
            let mut address = [0u8; ADDRESS_LENGTH];
            address.copy_from_slice(&result[..ADDRESS_LENGTH]);
            address
        };

        info!(
            "Client sending message to recipient address {:?}",
            hex::encode(recipient_address)
        );

        let packet = Packet::create_signed_encrypted(
            &self.auth,
            &self.encryption,
            recipient_dh_public_key,
            recipient_address,
            message,
            pow_difficulty,
            ttl,
            argon2_params,
        );

        // Send the packet to the connected node
        match TcpStream::connect(self.node_address).await {
            Ok(mut stream) => {
                let message = Message::Packet(packet);
                let data = bincode::serialize(&message).expect("Failed to serialize message");
                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to send packet: {:?}", e);
                }
            }
            Err(e) => {
                error!("Failed to connect to node: {:?}", e);
            }
        }
    }

    /// Subscribe to the node and receive all messages the node stores
    pub async fn subscribe_and_receive_messages(&self, pow_difficulty: usize) {
        // Connect to the node
        match TcpStream::connect(self.node_address).await {
            Ok(mut stream) => {
                // Send a Subscribe message without revealing the client's address
                let message = Message::Subscribe;
                let data = bincode::serialize(&message).expect("Failed to serialize message");
                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to send Subscribe message: {:?}", e);
                    return;
                }

                // Listen for incoming messages indefinitely
                let mut buffer = vec![0u8; 8192];

                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) => {
                            // Connection closed
                            info!("Connection closed by node");
                            break;
                        }
                        Ok(n) => {
                            if let Ok(message) = bincode::deserialize::<Message>(&buffer[..n]) {
                                match message {
                                    Message::Packet(packet) => {
                                        self.handle_incoming_packet(packet.clone()).await;
                                        // Check if the packet is addressed to the client
                                        if packet.recipient_address == self.address {
                                            // Attempt to decrypt the packet
                                            if let Some(plaintext) = packet.verify_and_decrypt(
                                                &self.encryption,
                                                pow_difficulty,
                                            ) {
                                                // Process the plaintext message
                                                info!(
                                                    "Received message: {:?}",
                                                    String::from_utf8_lossy(&plaintext)
                                                );
                                            } else {
                                                warn!("Failed to decrypt packet addressed to us");
                                            }
                                        } else {
                                            // Packet not addressed to us; ignore
                                        }
                                    }
                                    Message::UnsubscribeAck => {
                                        info!("Unsubscribed from node");
                                        break;
                                    }
                                    _ => {
                                        // Ignore other messages
                                    }
                                }
                            } else {
                                error!("Failed to deserialize message");
                            }
                        }
                        Err(e) => {
                            error!("Failed to read from node: {:?}", e);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to connect to node: {:?}", e);
            }
        }
    }
}
