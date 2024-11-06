// src/client/client.rs

use crate::authentication::Authentication;
use crate::encryption::Encryption;
use crate::packet::{Address, Packet, ADDRESS_LENGTH};
use crate::node::peer::Message;
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey as X25519PublicKey;
use ed25519_dalek::VerifyingKey;
use crate::serializable_argon2_params::SerializableArgon2Params;
use log::{info, error};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;

pub struct Client {
    pub auth: Authentication,
    pub encryption: Encryption,
    pub address: Address,
    pub node_address: SocketAddr,
}

impl Client {
    pub fn new(
        auth: Authentication,
        encryption: Encryption,
        node_address: SocketAddr,
    ) -> Self {
        // Compute the client's address
        let mut hasher = Sha256::new();
        hasher.update(&auth.verifying_key().to_bytes());
        hasher.update(encryption.our_public_key.as_bytes());
        let result = hasher.finalize();
        let mut address = [0u8; ADDRESS_LENGTH];
        address.copy_from_slice(&result[..ADDRESS_LENGTH]);

        info!("Client created with address {:?}", address);

        Client {
            auth,
            encryption,
            address,
            node_address,
        }
    }

    // Send a message to a recipient's address
    pub async fn send_message(
        &self,
        recipient_verifying_key: &VerifyingKey, // Recipient's verifying key
        recipient_dh_public_key: &X25519PublicKey, // Recipient's DH public key
        message: &[u8],
        pow_difficulty: usize,
        ttl: u64, // Added ttl parameter
        argon2_params: SerializableArgon2Params,
    ) {
        // Compute recipient's address
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
            "Client {:?} sending message to recipient address {:?}",
            self.address, recipient_address
        );

        let packet = Packet::create_signed_encrypted(
            &self.auth,
            &self.encryption,
            recipient_dh_public_key,
            recipient_address, // Pass recipient_address
            message,
            pow_difficulty,
            ttl, // Pass ttl
            argon2_params,
        );

        // Send the packet to the node
        let msg = Message::Packet(packet);

        match TcpStream::connect(self.node_address).await {
            Ok(mut stream) => {
                let data = match bincode::serialize(&msg) {
                    Ok(d) => d,
                    Err(e) => {
                        error!("Failed to serialize message: {:?}", e);
                        return;
                    }
                };
                let length = (data.len() as u32).to_be_bytes();
                if let Err(e) = stream.write_all(&length).await {
                    error!("Failed to send data length: {:?}", e);
                    return;
                }
                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to send message: {:?}", e);
                }
            }
            Err(e) => {
                error!("Failed to connect to node: {:?}", e);
            }
        }
    }

    // Retrieve all messages from the node and filter messages addressed to this client
    pub async fn receive_messages(&self, pow_difficulty: usize) -> Vec<Vec<u8>> {
        info!("Client {:?} retrieving messages from node", self.address);

        match TcpStream::connect(self.node_address).await {
            Ok(mut stream) => {
                // Send a request for all messages
                let request = Message::RequestAllMessages;
                let data = match bincode::serialize(&request) {
                    Ok(d) => d,
                    Err(e) => {
                        error!("Failed to serialize request: {:?}", e);
                        return Vec::new();
                    }
                };
                let length = (data.len() as u32).to_be_bytes();
                if let Err(e) = stream.write_all(&length).await {
                    error!("Failed to send data length: {:?}", e);
                    return Vec::new();
                }
                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to send message: {:?}", e);
                    return Vec::new();
                }

                // Read the length of the incoming message
                let mut length_bytes = [0u8; 4];
                if let Err(e) = stream.read_exact(&mut length_bytes).await {
                    error!("Error reading response length: {:?}", e);
                    return Vec::new();
                }
                let length = u32::from_be_bytes(length_bytes) as usize;

                // Read the message data
                let mut data = vec![0u8; length];
                if let Err(e) = stream.read_exact(&mut data).await {
                    error!("Error reading response data: {:?}", e);
                    return Vec::new();
                }

                // Deserialize the message
                let response: Message = match bincode::deserialize(&data) {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!("Failed to deserialize response: {:?}", e);
                        return Vec::new();
                    }
                };

                // Process the response
                if let Message::MessagesResponse(packets) = response {
                    // Decrypt and verify messages addressed to self
                    let messages: Vec<_> = packets
                        .iter()
                        .filter_map(|packet| {
                            // Check if the packet is addressed to self
                            if packet.recipient_address == self.address {
                                info!(
                                    "Client {:?} found packet addressed to self: {:?}",
                                    self.address, packet
                                );
                                let sender_public_key = X25519PublicKey::from(packet.dh_public_key);

                                packet.verify_and_decrypt(
                                    &self.encryption,
                                    &sender_public_key,
                                    pow_difficulty,
                                )
                            } else {
                                None // Ignore messages not addressed to self
                            }
                        })
                        .collect();

                    info!(
                        "Client {:?} retrieved {} messages",
                        self.address, messages.len()
                    );

                    messages
                } else {
                    error!("Unexpected response from node");
                    Vec::new()
                }
            }
            Err(e) => {
                error!("Failed to connect to node: {:?}", e);
                Vec::new()
            }
        }
    }
}
