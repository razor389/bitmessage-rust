// src/common.rs

use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use crate::{packet::{Address, AddressPrefix, Packet, ADDRESS_LENGTH}, serializable_argon2_params::SerializableArgon2Params};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    FindNode(Address),              // Find nodes closest to a given ID (Address)
    FindNodePrefix(AddressPrefix),
    Nodes(Vec<NodeInfo>),           // Response containing a list of NodeInfo
    NodesExtended(Vec<NodeInfoExtended>), // Response with extended node info
    GetPacket(Address),             // Request to get packets for a recipient address (no longer used)
    Packet(Packet),                 // A packet sent between nodes or to clients
    PacketNotFound,                 // Response indicating no packets were found (no longer used)
    Ping,                           // Ping message for node liveness checks
    Pong,                           // Pong response
    Subscribe,                      // Client subscribes to receive all stored packets
    Unsubscribe,                    // Client requests to unsubscribe
    UnsubscribeAck,                 // Acknowledgment of unsubscription (optional)
    Handshake(NodeInfoExtended),    // Handshake with node
    HandshakeAck(NodeInfoExtended), // Acknowledgment variant
    ClientHandshake, // Client initiates handshake
    ClientHandshakeAck(NodeInfoExtended), // Node responds with its info
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeInfo {
    pub id: [u8; 20],               // Node ID (160-bit hash)
    pub address: SocketAddr,        // Node's network address
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeInfoExtended {
    pub id: [u8; 20],
    pub address: SocketAddr,
    pub prefix_length: usize,
    pub pow_difficulty: usize,
    pub max_ttl: u64,
    pub min_argon2_params: SerializableArgon2Params,
}

/// Converts an Address to a bit vector
pub fn address_to_bits(address: &Address) -> Vec<bool> {
    let mut bits = Vec::with_capacity(ADDRESS_LENGTH * 8);
    for byte in address.iter() {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}

/// Converts a bit vector to an Address
pub fn bits_to_address(bits: &[bool]) -> Address {
    let mut address = [0u8; ADDRESS_LENGTH];
    for (i, bit) in bits.iter().enumerate() {
        if *bit {
            address[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    address
}