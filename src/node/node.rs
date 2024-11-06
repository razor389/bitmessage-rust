// src/node/node.rs

use crate::{packet::Packet, serializable_argon2_params::SerializableArgon2Params};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};
#[allow(unused_imports)]
use log::{info, debug, warn, error};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use std::time::{SystemTime, UNIX_EPOCH};

use super::peer::{Peer, Message};

pub struct Node {
    pub id: usize,
    pub prefix: Vec<u8>,
    pub messages: Arc<Mutex<HashMap<Vec<u8>, Packet>>>,
    pub peers: Arc<Mutex<HashMap<usize, Arc<Peer>>>>,
    pub pow_difficulty: usize,
    pub max_ttl: u64,
    pub blacklist: Arc<Mutex<HashSet<usize>>>,
    pub min_argon2_params: SerializableArgon2Params,
    pub address: SocketAddr,
    pub known_nodes: Arc<Mutex<HashSet<SocketAddr>>>,
    pub connect_sender: mpsc::Sender<SocketAddr>,
}

impl Node {
    pub async fn new(
        id: usize,
        prefix: Vec<u8>,
        pow_difficulty: usize,
        max_ttl: u64,
        min_argon2_params: SerializableArgon2Params,
        address: SocketAddr,
    ) -> Arc<Self> {
        let (connect_sender, mut connect_receiver) = mpsc::channel(100);

        let node = Arc::new(Node {
            id,
            prefix,
            messages: Arc::new(Mutex::new(HashMap::new())),
            peers: Arc::new(Mutex::new(HashMap::new())),
            pow_difficulty,
            max_ttl,
            blacklist: Arc::new(Mutex::new(HashSet::new())),
            min_argon2_params,
            address,
            known_nodes: Arc::new(Mutex::new(HashSet::new())),
            connect_sender,
        });

        let node_clone = Arc::clone(&node);
        tokio::spawn(async move {
            while let Some(addr) = connect_receiver.recv().await {
                let node_clone_inner = Arc::clone(&node_clone);
                if let Err(e) = node_clone_inner.connect_to_peer(addr).await {
                    error!("Failed to connect to discovered node {}: {:?}", addr, e);
                }
            }
        });

        node
    }

    pub async fn run(self: Arc<Self>) -> tokio::io::Result<()> {
        let listener = TcpListener::bind(self.address).await?;
        info!("Node {} listening on {}", self.id, self.address);

        loop {
            let (socket, addr) = listener.accept().await?;
            let node = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = node.handle_connection(socket, Some(addr)).await {
                    error!("Error handling connection from {}: {:?}", addr, e);
                }
            });
        }
    }

    async fn handle_connection(self: Arc<Self>, socket: TcpStream, addr: Option<SocketAddr>) -> tokio::io::Result<()> {
        let peer = Peer::new(socket, addr).await?;
        let peer_id = peer.id;
        self.peers.lock().await.insert(peer_id, Arc::new(peer.clone()));

        // Start receiving packets from the peer
        let node_clone = Arc::clone(&self);
        let peer_arc = Arc::new(peer);
        tokio::spawn(async move {
            peer_arc.receive_packets(node_clone).await;
        });

        Ok(())
    }

    pub async fn connect_to_peer(self: Arc<Self>, addr: SocketAddr) -> tokio::io::Result<()> {
        
        if addr == self.address {
            return Ok(()); // Avoid connecting to self
        }

        // Check if already connected
        {
            let peers = self.peers.lock().await;
            if peers.values().any(|peer| peer.address == Some(addr)) {
                info!("Node {} is already connected to {}", self.id, addr);
                return Ok(());
            }
        }

        match TcpStream::connect(addr).await {
            Ok(socket) => {
                let peer = Peer::new(socket, Some(addr)).await?;
                let peer_id = peer.id;
                let peer_arc = Arc::new(peer);
                self.peers.lock().await.insert(peer_id, Arc::clone(&peer_arc));

                // Start receiving packets from the peer
                let node_clone = Arc::clone(&self);
                let peer_clone = Arc::clone(&peer_arc);
                tokio::spawn(async move {
                    peer_clone.receive_packets(node_clone).await;
                });

                // Add to known nodes
                self.known_nodes.lock().await.insert(addr);
                info!("Node {} connected to peer at {}", self.id, addr);

                Ok(())
            }
            Err(e) => {
                error!("Node {} failed to connect to {}: {:?}", self.id, addr, e);
                Err(e)
            }
        }
    }

    // Gossip protocol

    pub fn start_gossip(self: &Arc<Self>) {
        let node = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                node.gossip_known_nodes().await;
            }
        });
    }

    async fn gossip_known_nodes(&self) {
        let peers = self.peers.lock().await;
        let known_nodes: Vec<SocketAddr> = self.known_nodes.lock().await.iter().cloned().collect();

        for peer in peers.values() {
            let peer = peer.clone();
            let nodes = known_nodes.clone();
            tokio::spawn(async move {
                if let Err(e) = peer.send_known_nodes(&nodes).await {
                    error!("Failed to send known nodes to peer {}: {:?}", peer.id, e);
                }
            });
        }
    }

    pub async fn update_known_nodes(&self, nodes: Vec<SocketAddr>) {
        for addr in nodes {
            if addr != self.address {
                let mut known_nodes = self.known_nodes.lock().await;
                if !known_nodes.contains(&addr) {
                    known_nodes.insert(addr);
                    // Send the address to the connect task
                    if let Err(e) = self.connect_sender.send(addr).await {
                        error!("Failed to send address {} to connection queue: {:?}", addr, e);
                    }
                }
            }
        }
    }

    // Check if Argon2id parameters are acceptable
    fn is_acceptable_argon2_params(&self, params: &SerializableArgon2Params) -> bool {
        params.m_cost >= self.min_argon2_params.m_cost
            && params.t_cost >= self.min_argon2_params.t_cost
            && params.p_cost >= self.min_argon2_params.p_cost
    }

    // Receive a packet and process it
    pub async fn receive_packet(self: Arc<Self>, packet: Packet, sender_id: Option<usize>) {
        info!(
            "Node {} received packet destined for address {:?}",
            self.id, packet.recipient_address
        );

        // If the sender is blacklisted, ignore the packet
        if let Some(s_id) = sender_id {
            let blacklist = self.blacklist.lock().await;
            if blacklist.contains(&s_id) {
                warn!(
                    "Node {} ignoring packet from blacklisted node {}",
                    self.id, s_id
                );
                return;
            }
        }

        // Check for Duplicate Packet
        {
            let messages = self.messages.lock().await;
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
                let mut blacklist = self.blacklist.lock().await;
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

        // Store the packet
        {
            let mut messages = self.messages.lock().await;
            messages.insert(packet.pow_hash.clone(), packet.clone());
            info!(
                "Node {} stored packet. Total messages stored: {}",
                self.id,
                messages.len()
            );
        }

        // Forward the packet to connected peers
        let peers = self.peers.lock().await;
        for peer in peers.values() {
            // Avoid forwarding back to the sender
            if Some(peer.id) == sender_id {
                continue;
            }

            // Check if the peer is blacklisted
            let blacklist = self.blacklist.lock().await;
            if blacklist.contains(&peer.id) {
                warn!(
                    "Node {} not forwarding to blacklisted peer {}",
                    self.id, peer.id
                );
                continue;
            }

            // Forward the packet
            let peer = peer.clone();
            let packet_clone = packet.clone();
            tokio::spawn(async move {
                let message = Message::Packet(packet_clone);
                if let Err(e) = peer.send_message(&message).await {
                    error!("Failed to forward packet to peer {}: {:?}", peer.id, e);
                }
            });
        }
    }

    // Retrieve all messages stored in the node
    pub async fn get_all_messages(&self) -> Vec<Packet> {
        self.purge_expired_messages().await; // Purge expired messages before returning
        let messages = self.messages.lock().await;
        info!(
            "Node {} providing {} messages",
            self.id,
            messages.len()
        );
        messages.values().cloned().collect()
    }

    // Purge expired messages
    async fn purge_expired_messages(&self) {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut messages = self.messages.lock().await;
        messages.retain(|_, packet| {
            current_time <= packet.timestamp + packet.ttl
        });
    }
}
