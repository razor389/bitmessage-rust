// src/node/node.rs

use crate::{
    common::{HandshakeInfo, Message}, packet::Packet, serializable_argon2_params::SerializableArgon2Params
};
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

use super::peer::Peer;

pub struct Node {
    pub id: usize,
    pub prefix: Vec<u8>,
    pub messages: Arc<Mutex<HashMap<Vec<u8>, Packet>>>,
    pub peers: Arc<Mutex<HashMap<usize, Arc<Peer>>>>,
    pub pow_difficulty: usize,
    pub max_ttl: u64,
    pub blacklist: Arc<Mutex<HashSet<SocketAddr>>>,
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

            // Refuse connection if IP is blacklisted
            if self.blacklist.lock().await.contains(&addr) {
                warn!("Refusing connection from blacklisted IP: {}", addr);
                continue;
            }

            tokio::spawn(async move {
                if let Err(e) = node.handle_connection(socket, Some(addr)).await {
                    error!("Error handling connection from {}: {:?}", addr, e);
                }
            });
        }
    }

    pub async fn send_handshake(&self, peer: &Peer) -> tokio::io::Result<()> {
        let handshake = HandshakeInfo {
            prefix: self.prefix.clone(),
            max_ttl: self.max_ttl,
            pow_difficulty: self.pow_difficulty,
            min_argon2_params: self.min_argon2_params.clone(),
            known_nodes: self.get_known_nodes_snapshot().await,
            is_node: true, // Assuming this node wants to participate in gossip and forwarding
            id: self.id,
            address: self.address,
        };
        let message = Message::Handshake(handshake);
        peer.send_message(&message).await
    }

    pub async fn get_known_nodes_snapshot(&self) -> Vec<SocketAddr> {
        let known_nodes = self.known_nodes.lock().await;
        known_nodes.iter().cloned().collect()
    }

    pub async fn handle_connection(self: Arc<Self>, socket: TcpStream, addr: Option<SocketAddr>) -> tokio::io::Result<()> {
        if let Some(ip) = addr {
            // Refuse handling if IP is blacklisted
            if self.blacklist.lock().await.contains(&ip) {
                warn!("Ignoring connection from blacklisted IP: {}", ip);
                return Ok(());
            }
        }

        let peer = Peer::new(socket, addr).await?;
        let peer_id = peer.id;
        self.peers.lock().await.insert(peer_id, Arc::new(peer.clone()));

        // Send handshake immediately after establishing connection
        self.send_handshake(&peer).await?;

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

        // Refuse connection if IP is blacklisted
        if self.blacklist.lock().await.contains(&addr) {
            warn!("Node {} refusing to connect to blacklisted IP: {}", self.id, addr);
            return Ok(());
        }

        match TcpStream::connect(addr).await {
            Ok(socket) => {
                let peer = Peer::new(socket, Some(addr)).await?;
                let peer_id = peer.id;
                let peer_arc = Arc::new(peer.clone());
                self.peers.lock().await.insert(peer_id, Arc::clone(&peer_arc));

                // Send handshake immediately after connecting
                self.send_handshake(&peer).await?;

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
        let known_nodes: Vec<SocketAddr> = {
            let known_nodes = self.known_nodes.lock().await;
            known_nodes.iter().cloned().collect()
        };

        for peer in peers.values() {
            if let Some(addr) = peer.address {
                // Skip if the peer's address is blacklisted
                if self.blacklist.lock().await.contains(&addr) {
                    warn!("Skipping blacklisted IP {} during gossip", addr);
                    continue;
                }
            }

            // Check if handshake is complete
            {
                let handshake = peer.handshake_info.lock().await;
                if handshake.is_none() {
                    warn!(
                        "Skipping gossip to peer {} as handshake is not complete",
                        peer.id
                    );
                    continue;
                }
            }

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
                // Check if the addr is blacklisted
                {
                    let blacklist = self.blacklist.lock().await;
                    if blacklist.contains(&addr) {
                        warn!("Not adding blacklisted IP {} to known nodes", addr);
                        continue;
                    }
                }

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

    // Handle the HandshakeInfo
    pub async fn handle_handshake(&self, peer: Arc<Peer>, handshake: HandshakeInfo) {
        // Validate handshake parameters
        if !self.is_acceptable_handshake(&handshake) {
            warn!(
                "Node {} received unacceptable handshake parameters from peer {}",
                self.id, peer.id
            );
            // Optionally, you can blacklist the peer or close the connection
            if let Some(addr) = peer.address {
                self.blacklist_ip(addr).await;
            }
            return;
        }

        // Update node's known nodes with peer's known nodes
        self.update_known_nodes(handshake.known_nodes).await;

        if handshake.is_node {
            info!("Peer {} is a node and will participate in gossip and forwarding", peer.id);
            // Implement any additional logic for nodes here
        } else {
            info!("Peer {} is a client and will only send/receive messages", peer.id);
            // Implement any client-specific logic here
        }

        // Additional handling based on handshake info can be done here
    }

    fn is_acceptable_handshake(&self, handshake: &HandshakeInfo) -> bool {
        // Validate recipient prefix
        if !handshake.prefix.starts_with(&self.prefix) {
            return false;
        }

        // Validate max_ttl
        if handshake.max_ttl > self.max_ttl {
            return false;
        }

        // Validate PoW difficulty
        if handshake.pow_difficulty < self.pow_difficulty {
            return false;
        }

        // Validate Argon2 parameters
        self.is_acceptable_argon2_params(&handshake.min_argon2_params)
    }

    // Receive a packet and process it
    pub async fn receive_packet(&self, packet: Packet, sender_id: Option<usize>) {
        info!(
            "Node {} received packet destined for address {:?}",
            self.id, packet.recipient_address
        );

        // Ensure that the peer has completed the handshake
        if let Some(s_id) = sender_id {
            let peers = self.peers.lock().await;
            if let Some(peer) = peers.get(&s_id) {
                let handshake = peer.handshake_info.lock().await;
                if handshake.is_none() {
                    warn!(
                        "Node {} received a packet from peer {} before completing handshake",
                        self.id, s_id
                    );
                    return;
                }
            }
        }

        // If the sender is blacklisted, ignore the packet
        if let Some(s_id) = sender_id {
            let peers = self.peers.lock().await;
            if let Some(peer) = peers.get(&s_id) {
                if let Some(addr) = peer.address {
                    let blacklist = self.blacklist.lock().await;
                    if blacklist.contains(&addr) {
                        warn!(
                            "Node {} ignoring packet from blacklisted IP {}",
                            self.id, addr
                        );
                        return;
                    }
                }
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
                let peers = self.peers.lock().await;
                if let Some(peer) = peers.get(&s_id) {
                    if let Some(addr) = peer.address {
                        self.blacklist_ip(addr).await;
                    }
                }
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

        // Store the packet if the recipient address matches the node's prefix
        if packet.recipient_address.starts_with(&self.prefix){
            let mut messages = self.messages.lock().await;
            messages.insert(packet.pow_hash.clone(), packet.clone());
            info!(
                "Node {} stored packet. Total messages stored: {}",
                self.id,
                messages.len()
            );
        }

        // Forward the packet to connected peers (TODO: Only if their prefix matches recipient address)
        let peers = self.peers.lock().await;
        for peer in peers.values() {
            // Avoid forwarding back to the sender
            if Some(peer.id) == sender_id {
                continue;
            }

            // Check if the peer is blacklisted
            if let Some(addr) = peer.address {
                let blacklist = self.blacklist.lock().await;
                if blacklist.contains(&addr) {
                    warn!(
                        "Node {} not forwarding to blacklisted peer {} at IP {}",
                        self.id, peer.id, addr
                    );
                    continue;
                }
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

    // Blacklist an IP address and remove it from known nodes and peers
    pub async fn blacklist_ip(&self, addr: SocketAddr) {
        {
            let mut blacklist = self.blacklist.lock().await;
            if !blacklist.insert(addr) {
                // IP was already blacklisted
                return;
            }
            info!("Node {} blacklisted IP {}", self.id, addr);
        }

        // Remove from known nodes
        {
            let mut known_nodes = self.known_nodes.lock().await;
            if known_nodes.remove(&addr) {
                info!("Node {} removed IP {} from known nodes", self.id, addr);
            }
        }

        // Disconnect if connected
        let peer_to_remove = {
            let peers = self.peers.lock().await;
            peers.values()
                .find(|peer| peer.address == Some(addr))
                .map(|peer| peer.id)
        };

        if let Some(peer_id) = peer_to_remove {
            let mut peers = self.peers.lock().await;
            peers.remove(&peer_id);
            info!("Node {} disconnected from blacklisted peer {}", self.id, peer_id);
        }

        // Ensure we don't try to reconnect
        // If addr is in the connect queue, it might be attempted again.
        // We might need to implement logic to prevent this if necessary.
    }
}
