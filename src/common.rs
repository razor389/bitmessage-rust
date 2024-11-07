// src/common.rs

use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use crate::{packet::Packet, serializable_argon2_params::SerializableArgon2Params};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeInfo {
    pub prefix: Vec<u8>,
    pub max_ttl: u64,
    pub pow_difficulty: usize,
    pub min_argon2_params: SerializableArgon2Params,
    pub known_nodes: Vec<SocketAddr>,
    pub is_node: bool, // Indicates if the peer wants to participate in gossip and forwarding
    pub id: usize,      // Peer’s unique ID
    pub address: SocketAddr, // Peer’s socket address
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    Packet(Packet),
    KnownNodes(Vec<SocketAddr>),
    RequestAllMessages,
    MessagesResponse(Vec<Packet>),
    Handshake(HandshakeInfo), // New variant for handshake
}
