// src/node.rs

use crate::packet::Packet;
use std::sync::{Arc, Mutex};
#[allow(unused_imports)]
use log::{info, debug, warn, error};

pub struct Node {
    pub prefix: Vec<u8>, // The address prefix this node is responsible for
    pub messages: Arc<Mutex<Vec<Packet>>>, // Store all messages in a single vector
    pub connected_nodes: Arc<Mutex<Vec<Arc<Node>>>>, // Wrap in Arc<Mutex<...>> to allow mutation
}

impl Node {
    pub fn new(prefix: Vec<u8>) -> Self {
        info!("Node created with prefix {:?}", prefix);
        Node {
            prefix,
            messages: Arc::new(Mutex::new(Vec::new())),
            connected_nodes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    // Connect to another node
    pub fn connect(&self, node: Arc<Node>) {
        let mut connected_nodes = self.connected_nodes.lock().unwrap();
        info!(
            "Node with prefix {:?} connected to node with prefix {:?}",
            self.prefix, node.prefix
        );
        connected_nodes.push(node);
    }

    // Receive a packet and process it
    pub fn receive_packet(self: Arc<Self>, packet: Packet) {
        info!(
            "Node with prefix {:?} received packet destined for address {:?}",
            self.prefix, packet.recipient_address
        );
        let packet_address = packet.recipient_address; // Use recipient_address

        // Check if the packet's recipient address matches the node's prefix
        if packet_address.starts_with(&self.prefix) {
            // Store the packet
            let mut messages = self.messages.lock().unwrap();
            messages.push(packet.clone());
            info!(
                "Packet stored at node with prefix {:?}. Total messages stored: {}",
                self.prefix,
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
            // Avoid forwarding to nodes that already received the packet
            if packet_address.starts_with(&node.prefix) {
                info!(
                    "Node with prefix {:?} forwarding packet to node with prefix {:?}",
                    self.prefix, node.prefix
                );
                node.clone().receive_packet(packet.clone());
            } else {
                debug!(
                    "Node with prefix {:?} not forwarding to node with prefix {:?} as prefix does not match",
                    self.prefix, node.prefix
                );
            }
        }
    }

    // Retrieve all messages stored in the node
    pub fn get_all_messages(&self) -> Vec<Packet> {
        let messages = self.messages.lock().unwrap();
        info!(
            "Node with prefix {:?} providing {} messages",
            self.prefix,
            messages.len()
        );
        messages.clone()
    }
}
