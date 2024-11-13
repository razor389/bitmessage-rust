// src/common.rs

use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use crate::{packet::{Address, Packet}, serializable_argon2_params::SerializableArgon2Params};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    FindNode(Address),              // Find nodes closest to a given ID (Address)
    Nodes(Vec<NodeInfo>),           // Response containing a list of NodeInfo
    GetPacket(Address),             // Request to get packets for a recipient address (no longer used)
    Packet(Packet),                 // A packet sent between nodes or to clients
    PacketNotFound,                 // Response indicating no packets were found (no longer used)
    Ping,                           // Ping message for node liveness checks
    Pong,                           // Pong response
    Subscribe,                      // Client subscribes to receive all stored packets
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