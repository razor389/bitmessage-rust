// src/client.rs

use crate::authentication::Authentication;
use crate::encryption::Encryption;
use crate::node::Node;
use crate::packet::{Address, Packet, ADDRESS_LENGTH};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use x25519_dalek::PublicKey as X25519PublicKey;
use ed25519_dalek::VerifyingKey;
#[allow(unused_imports)]
use log::{info, debug, warn, error};

pub struct Client {
    pub auth: Authentication,
    pub encryption: Encryption,
    pub connected_node: Arc<Node>,
    pub address: Address,
}

impl Client {
    pub fn new(
        auth: Authentication,
        encryption: Encryption,
        connected_node: Arc<Node>,
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
            connected_node,
            address,
        }
    }

    // Send a message to a recipient's address
    pub fn send_message(
        &self,
        recipient_verifying_key: &VerifyingKey, // Recipient's verifying key
        recipient_dh_public_key: &X25519PublicKey, // Recipient's DH public key
        message: &[u8],
        pow_difficulty: usize,
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
        );

        // Send the packet to the connected node
        self.connected_node
            .clone()
            .receive_packet(packet);
    }

    // Retrieve all messages from the node and filter messages addressed to this client
    pub fn receive_messages(&self, pow_difficulty: usize) -> Vec<Vec<u8>> {
        info!("Client {:?} retrieving messages from node", self.address);

        let packets = self.connected_node.get_all_messages();

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
        info!("Client {:?} retrieved {} messages", self.address, messages.len());

        messages
    }
}
