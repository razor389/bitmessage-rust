// src/client/client.rs

use crate::{
    authentication::Authentication,
    encryption::Encryption,
    packet::{Packet, Address, ADDRESS_LENGTH},
    serializable_argon2_params::SerializableArgon2Params,
    common::{HandshakeInfo, Message},
};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey as X25519PublicKey;
use ed25519_dalek::VerifyingKey;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use log::{info, error};
use bincode;

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

        // Send the packet to the node with handshake
        match TcpStream::connect(self.node_address).await {
            Ok(mut stream) => {
                // Perform handshake
                if let Err(e) = self.perform_handshake(&mut stream).await {
                    error!("Handshake failed: {:?}", e);
                    return;
                }

                // Send the packet
                let msg = Message::Packet(packet);
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
                // Perform handshake
                if let Err(e) = self.perform_handshake(&mut stream).await {
                    error!("Handshake failed: {:?}", e);
                    return Vec::new();
                }

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

    // Perform handshake with the node
    async fn perform_handshake(&self, stream: &mut TcpStream) -> tokio::io::Result<()> {
        // Create HandshakeInfo
        let handshake = HandshakeInfo {
            prefix: vec![], // Assuming empty prefix for client; adjust as needed
            max_ttl: 3600,
            pow_difficulty: 1,
            min_argon2_params: SerializableArgon2Params::default(), // Define default or specific params
            known_nodes: vec![], // Clients may not have known nodes
            is_node: false, // Clients are not nodes
            id: 0,          // Assign a unique ID for the client if needed
            address: self.node_address, // Clients may not have their own address; adjust as needed
        };

        // Serialize and send the handshake
        let msg = Message::Handshake(handshake);
        let data = match bincode::serialize(&msg) {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to serialize handshake message: {:?}", e);
                return Err(tokio::io::Error::new(tokio::io::ErrorKind::Other, e));
            }
        };
        let length = (data.len() as u32).to_be_bytes();
        stream.write_all(&length).await?;
        stream.write_all(&data).await?;

        // Await node's handshake response
        let reader = stream;

        // Read the length of the incoming message
        let mut length_bytes = [0u8; 4];
        reader.read_exact(&mut length_bytes).await?;
        let length = u32::from_be_bytes(length_bytes) as usize;

        // Read the message data
        let mut data = vec![0u8; length];
        reader.read_exact(&mut data).await?;

        // Deserialize the message
        let response: Message = match bincode::deserialize(&data) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Failed to deserialize handshake response: {:?}", e);
                return Err(tokio::io::Error::new(tokio::io::ErrorKind::Other, e));
            }
        };

        // Process the handshake response
        match response {
            Message::Handshake(node_handshake) => {
                info!(
                    "Client {:?} received handshake from node: {:?}",
                    self.address, node_handshake
                );
                // Optionally, you can validate node's handshake here
                Ok(())
            }
            _ => {
                error!("Client expected handshake response but received a different message.");
                Err(tokio::io::Error::new(tokio::io::ErrorKind::Other, "Invalid handshake response"))
            }
        }
    }
}

// Implement Default for SerializableArgon2Params if not already implemented
impl Default for SerializableArgon2Params {
    fn default() -> Self {
        SerializableArgon2Params {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
            output_length: Some(32),
        }
    }
}
