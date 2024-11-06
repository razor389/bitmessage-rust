// src/node.rs

use crate::{packet::Packet, serializable_argon2_params::SerializableArgon2Params};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
#[allow(unused_imports)]
use log::{info, debug, warn, error};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Node {
    pub id: usize, // Unique identifier for the node
    pub prefix: Vec<u8>, // The address prefix this node is responsible for
    pub messages: Arc<Mutex<HashMap<Vec<u8>, Packet>>>, // Store messages in a hash map
    pub connected_nodes: Arc<Mutex<Vec<Arc<Node>>>>, // Wrap in Arc<Mutex<...>> to allow mutation
    pub pow_difficulty: usize, // PoW difficulty level
    pub max_ttl: u64,          // Max TTL in seconds
    pub blacklist: Arc<Mutex<HashSet<usize>>>, // Blacklisted node IDs
    pub min_argon2_params: SerializableArgon2Params, // Use serializable version
}

impl Node {
    pub fn new(id: usize, prefix: Vec<u8>, pow_difficulty: usize, max_ttl: u64, min_argon2_params: SerializableArgon2Params,) -> Self {
        info!("Node {} created with prefix {:?}", id, prefix);
        Node {
            id,
            prefix,
            messages: Arc::new(Mutex::new(HashMap::new())),
            connected_nodes: Arc::new(Mutex::new(Vec::new())),
            pow_difficulty,
            max_ttl,
            blacklist: Arc::new(Mutex::new(HashSet::new())),
            min_argon2_params,
        }
    }

    // Check if Argon2id parameters are acceptable
    fn is_acceptable_argon2_params(&self, params: &SerializableArgon2Params) -> bool {
        params.m_cost >= self.min_argon2_params.m_cost
            && params.t_cost >= self.min_argon2_params.t_cost
            && params.p_cost >= self.min_argon2_params.p_cost
    }

    // Connect to another node
    pub fn connect(&self, node: Arc<Node>) {
        let mut connected_nodes = self.connected_nodes.lock().unwrap();
        info!(
            "Node {} connected to node {} with prefix {:?}",
            self.id, node.id, node.prefix
        );
        connected_nodes.push(node);
    }

    // Receive a packet and process it
    pub fn receive_packet(self: Arc<Self>, packet: Packet, sender_id: Option<usize>) {
        info!(
            "Node {} received packet destined for address {:?}",
            self.id, packet.recipient_address
        );

        // If the sender is blacklisted, ignore the packet
        if let Some(s_id) = sender_id {
            let blacklist = self.blacklist.lock().unwrap();
            if blacklist.contains(&s_id) {
                warn!(
                    "Node {} ignoring packet from blacklisted node {}",
                    self.id, s_id
                );
                return;
            }
        }

        // **Check for Duplicate Packet**
    {
        let messages = self.messages.lock().unwrap();
        if messages.contains_key(&packet.pow_hash) {
            info!(
                "Node {} already has packet with pow_hash {:?}, ignoring duplicate",
                self.id, packet.pow_hash
            );
            return; // Ignore the duplicate packet
        }
    }

        // Verify Argon2id parameters
        if !self.is_acceptable_argon2_params(&packet.argon2_params) {
            warn!(
                "Node {} received packet with unacceptable Argon2id parameters from node {:?}",
                self.id, sender_id
            );
            return; // Discard the packet
        }

        // Verify PoW
        if !packet.verify_pow(self.pow_difficulty) {
            warn!(
                "Node {} received packet with invalid PoW from node {:?}",
                self.id, sender_id
            );

            // Blacklist the sender if known
            if let Some(s_id) = sender_id {
                let mut blacklist = self.blacklist.lock().unwrap();
                blacklist.insert(s_id);
                warn!("Node {} blacklisted node {}", self.id, s_id);
            }

            // Do not process the packet further
            return;
        }

        // Check TTL
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if packet.ttl > self.max_ttl {
            warn!(
                "Node {} received packet with TTL {} exceeding max TTL {}",
                self.id, packet.ttl, self.max_ttl
            );
            return; // Discard the packet
        }

        if current_time > packet.timestamp + packet.ttl {
            warn!(
                "Node {} received packet with expired TTL",
                self.id
            );
            return; // Discard the packet
        }

        let packet_address = packet.recipient_address;

        // Store the packet if the recipient address matches the node's prefix
        if packet_address.starts_with(&self.prefix) {
            // Store the packet
            let mut messages = self.messages.lock().unwrap();
            messages.insert(packet.pow_hash.clone(), packet.clone());
            info!(
                "Node {} stored packet. Total messages stored: {}",
                self.id,
                messages.len()
            );
        }

        // Forward the packet to connected nodes whose prefixes match the recipient address
        let connected_nodes = self.connected_nodes.lock().unwrap();
        for node in connected_nodes.iter() {
            // Avoid forwarding back to self
            if Arc::ptr_eq(node, &self) {
                continue;
            }

            // Check if the node is blacklisted
            let blacklist = self.blacklist.lock().unwrap();
            if blacklist.contains(&node.id) {
                warn!(
                    "Node {} not forwarding to blacklisted node {}",
                    self.id, node.id
                );
                continue;
            }

            if packet_address.starts_with(&node.prefix) {
                info!(
                    "Node {} forwarding packet to node {} with prefix {:?}",
                    self.id, node.id, node.prefix
                );
                node.clone().receive_packet(packet.clone(), Some(self.id));
            } else {
                debug!(
                    "Node {} not forwarding to node {} as prefix does not match",
                    self.id, node.id
                );
            }
        }
    }

    // Retrieve all messages stored in the node
    pub fn get_all_messages(&self) -> Vec<Packet> {
        self.purge_expired_messages(); // Purge expired messages before returning
        let messages = self.messages.lock().unwrap();
        info!(
            "Node {} with prefix {:?} providing {} messages",
            self.id,
            self.prefix,
            messages.len()
        );
        messages.values().cloned().collect()
    }

    // Purge expired messages
    fn purge_expired_messages(&self) {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut messages = self.messages.lock().unwrap();
        messages.retain(|_, packet| {
            current_time <= packet.timestamp + packet.ttl
        });
    }
}
