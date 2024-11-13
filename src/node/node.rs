// src/node.rs

use crate::packet::{Packet, Address, ADDRESS_LENGTH};
use crate::common::{Message, NodeInfo, NodeInfoExtended};
use crate::serializable_argon2_params::SerializableArgon2Params;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::sync::broadcast::{self, Sender as BroadcastSender};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use sha2::{Sha256, Digest};
use log::{info, warn, error};
use tokio::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH}; // Added for timestamp management

type NodeId = [u8; 20]; // 160-bit node ID

/// Kademlia Node
pub struct Node {
    pub id: NodeId,
    pub address: SocketAddr,
    pub prefix_length: usize, // Number of bits in the prefix
    pub routing_table: Arc<Mutex<RoutingTable>>,
    pub packet_store: Arc<Mutex<HashMap<Vec<u8>, Packet>>>, // Store packets by pow_hash
    pub blacklist: Arc<Mutex<HashMap<IpAddr, Instant>>>, // IP blacklist with timeout
    pub network_tx: mpsc::Sender<NetworkMessage>,
    pub network_rx: Arc<Mutex<mpsc::Receiver<NetworkMessage>>>,
    pub pow_difficulty: usize, // Difficulty for PoW verification
    pub subscribers: Arc<Mutex<Vec<BroadcastSender<Packet>>>>, // List of subscriber channels
    pub max_ttl: u64, // Maximum allowed TTL in seconds
    pub min_argon2_params: SerializableArgon2Params, // Minimum Argon2 parameters
    pub cleanup_interval: Duration, 
    pub blacklist_duration: Duration,
    pub node_requirements: Arc<Mutex<HashMap<NodeId, NodeInfoExtended>>>,
}

pub enum NetworkMessage {
    Incoming { stream: TcpStream },
    Outgoing { message: Message, address: SocketAddr },
}

impl Node {
    /// Create a new node
    pub async fn new(
        public_key: &[u8],
        address: SocketAddr,
        prefix_length: usize,
        pow_difficulty: usize,
        max_ttl: u64, // New parameter
        min_argon2_params: SerializableArgon2Params, // New parameter
        cleanup_interval: Duration, 
        blacklist_duration: Duration,
    ) -> Arc<Self> {
        // Generate node ID by hashing the node's public key
        let id = generate_node_id(public_key);

        let (network_tx, network_rx) = mpsc::channel(100);
        let node = Arc::new(Node {
            id,
            address,
            prefix_length,
            routing_table: Arc::new(Mutex::new(RoutingTable::new(id))),
            packet_store: Arc::new(Mutex::new(HashMap::new())),
            blacklist: Arc::new(Mutex::new(HashMap::new())),
            network_tx,
            network_rx: Arc::new(Mutex::new(network_rx)),
            pow_difficulty,
            subscribers: Arc::new(Mutex::new(Vec::new())),
            max_ttl,
            min_argon2_params,
            cleanup_interval,
            blacklist_duration,
            node_requirements: Arc::new(Mutex::new(HashMap::new())),
        });

        let node_clone = node.clone();
        tokio::spawn(async move {
            node_clone.run().await;
        });

        // Spawn the cleanup task
        let node_clone_for_cleanup = node.clone();
        tokio::spawn(async move {
            node_clone_for_cleanup.cleanup_expired_packets().await;
        });

        node
    }

    /// Main loop to accept incoming connections and handle network messages
    pub async fn run(self: Arc<Self>) {
        // Start listening for incoming connections
        let listener = TcpListener::bind(self.address).await.expect("Failed to bind");
        info!("Node {} listening on {}", hex::encode(self.id), self.address);

        // Spawn task to accept incoming connections
        let node_clone = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let _ = node_clone.network_tx.send(NetworkMessage::Incoming { stream }).await;
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {:?}", e);
                    }
                }
            }
        });

        // Handle network messages
        while let Some(message) = self.network_rx.lock().await.recv().await {
            match message {
                NetworkMessage::Incoming { stream } => {
                    // Handle incoming connection
                    let node_clone = self.clone();
                    tokio::spawn(async move {
                        node_clone.handle_connection(stream).await;
                    });
                }
                NetworkMessage::Outgoing { message, address } => {
                    // Send message to address
                    let node_clone = self.clone();
                    tokio::spawn(async move {
                        node_clone.send_message(message, address).await;
                    });
                }
            }
        }
    }

    /// Periodically cleans up expired packets based on their TTL
    async fn cleanup_expired_packets(self: Arc<Self>) {
        loop {
            // Sleep for the defined cleanup interval before next cleanup
            tokio::time::sleep(self.cleanup_interval).await;

            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let expired_keys = {
                let store = self.packet_store.lock().await;
                store
                    .iter()
                    .filter_map(|(key, packet)| {
                        if packet.timestamp + packet.ttl <= current_time {
                            Some(key.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<Vec<u8>>>()
            };

            if !expired_keys.is_empty() {
                let mut store = self.packet_store.lock().await;
                for key in expired_keys {
                    if let Some(packet) = store.remove(&key) {
                        info!(
                            "Removed expired packet with pow_hash: {}",
                            hex::encode(&packet.pow_hash)
                        );
                    }
                }
            }

            // Cleanup expired blacklist entries
            let expired_blacklist = {
                let blacklist = self.blacklist.lock().await;
                blacklist
                    .iter()
                    .filter_map(|(ip, timeout)| {
                        if Instant::now() >= *timeout {
                            Some(*ip)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<IpAddr>>()
            };

            if !expired_blacklist.is_empty() {
                let mut blacklist = self.blacklist.lock().await;
                for ip in expired_blacklist {
                    blacklist.remove(&ip);
                    info!("Removed IP from blacklist: {}", ip);
                }
            }
        }
    }

    /// Handle an incoming connection
    async fn handle_connection(self: Arc<Self>, mut stream: TcpStream) {
        let mut buffer = vec![0u8; 8192]; // Adjust buffer size as needed

        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!("Failed to get peer address: {:?}", e);
                return;
            }
        };

        let peer_ip = peer_addr.ip();

        // Check if the IP is blacklisted
        if self.is_blacklisted(&peer_ip).await {
            warn!("Connection from blacklisted IP: {}", peer_ip);
            return;
        }

        // Receive the handshake from the connecting node
        let n = match stream.read(&mut buffer).await {
            Ok(n) => n,
            Err(e) => {
                error!("Failed to read from stream: {:?}", e);
                return;
            }
        };
        
        let message: Message = match bincode::deserialize(&buffer[..n]) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Failed to deserialize message: {:?}", e);
                return;
            }
        };

        match message {
            Message::ClientHandshake => {
                // Send node info to client
                let handshake_ack = Message::ClientHandshakeAck(self.get_node_info_extended());
                let data = bincode::serialize(&handshake_ack).expect("Failed to serialize handshake acknowledgement");
                stream.write_all(&data).await.expect("Failed to write handshake ack");
                // Proceed to handle further client messages
            }
            Message::Handshake(node_info) =>{
                self.update_routing_table_extended(node_info.clone()).await;

                // Send back our handshake
                let handshake_ack = Message::HandshakeAck(self.get_node_info_extended());
                let data = bincode::serialize(&handshake_ack).expect("Failed to serialize handshake acknowledgement");
                stream.write_all(&data).await.expect("Failed to write handshake ack");
            }
            _ =>{
                warn!("Expected handshake message");
                return;
            }
        }

        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    // Connection closed
                    break;
                }
                Ok(n) => {
                    // Deserialize the message
                    if let Ok(message) = bincode::deserialize::<Message>(&buffer[..n]) {
                        let sender_address = peer_addr;

                        match message {
                            Message::Subscribe => {
                                // Handle subscription
                                let node_clone = self.clone();
                                tokio::spawn(async move {
                                    node_clone.handle_subscribe(sender_address, stream).await;
                                });
                                // After subscribing, we no longer read from this stream
                                break;
                            }
                            _ => {
                                self.handle_message(message, sender_address).await;
                            }
                        }
                    } else {
                        error!("Failed to deserialize message from {}", peer_ip);
                        self.blacklist_ip(&peer_ip).await;
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to read from connection: {:?}", e);
                    break;
                }
            }
        }
    }

    /// Handle an incoming message
    async fn handle_message(&self, message: Message, sender_address: SocketAddr) {
        match message {
            Message::FindNode(target_id) => {
                let closest_nodes = self.find_closest_nodes(&target_id).await;
                let response = Message::Nodes(closest_nodes);
                self.send_message(response, sender_address).await;
            }
            Message::Nodes(nodes) => {
                // Update routing table with received nodes
                for node_info in nodes {
                    self.update_routing_table(node_info).await;
                }
            }
            Message::Packet(packet) => {
                self.handle_packet(packet, sender_address).await;
            }
            Message::Ping => {
                let response = Message::Pong;
                self.send_message(response, sender_address).await;
            }
            Message::Pong => {
                // Update routing table to mark node as responsive
                self.mark_node_alive(sender_address).await;
            }
            _ => {
                warn!("Received unknown message type from {}", sender_address);
            }
        }
    }

    /// Handle a Subscribe message
    async fn handle_subscribe(self: Arc<Self>, sender_address: SocketAddr, mut stream: TcpStream) {
        let (tx, mut rx) = broadcast::channel::<Packet>(100);

        {
            let mut subscribers = self.subscribers.lock().await;
            subscribers.push(tx.clone());
        }

        info!("Client {} subscribed", sender_address);

        // Send all stored packets to the subscriber
        let packets = {
            let store = self.packet_store.lock().await;
            store.values().cloned().collect::<Vec<Packet>>()
        };

        for packet in packets {
            let _ = tx.send(packet);
        }

        // Continuously send new packets to the subscriber
        let self_clone = self.clone();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(packet) => {
                        let message = Message::Packet(packet);
                        let data = bincode::serialize(&message).expect("Failed to serialize message");
                        if let Err(e) = stream.write_all(&data).await {
                            error!("Failed to send message to subscriber: {:?}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Broadcast channel error: {:?}", e);
                        break;
                    }
                }
            }

            // Remove subscriber when done
            {
                let mut subscribers = self_clone.subscribers.lock().await;
                subscribers.retain(|s| s.receiver_count() > 0);
            }
        });
    }

    /// Handle a Packet message
    async fn handle_packet(&self, packet: Packet, sender_address: SocketAddr) {
        // Step 1: Verify TTL
        if packet.ttl > self.max_ttl {
            warn!(
                "Packet TTL {} exceeds max_ttl {} from {}",
                packet.ttl, self.max_ttl, sender_address
            );
            self.blacklist_ip(&sender_address.ip()).await;
            return;
        }

        // Step 2: Verify Argon2 parameters
        if !packet.argon2_params.meets_min(&self.min_argon2_params) {
            warn!(
                "Packet argon2_params {:?} below min_argon2_params {:?} from {}",
                packet.argon2_params, self.min_argon2_params, sender_address
            );
            self.blacklist_ip(&sender_address.ip()).await;
            return;
        }

        // Step 3: Verify PoW
        if !packet.verify_pow(self.pow_difficulty) {
            warn!("Invalid PoW from {}", sender_address);
            self.blacklist_ip(&sender_address.ip()).await;
            return;
        }

        // Step 4: Store the packet if we should
        if self.should_store_packet(&packet.recipient_address) {
            self.store_packet(packet.clone()).await; // Clone because we'll use it later
            info!("Stored packet on node {}", hex::encode(self.id));
        }

        // Step 5: Forward the packet to other nodes with matching prefixes
        self.forward_packet(packet, sender_address).await;
    }

    /// Determine if the node should store the packet based on its prefix
    fn should_store_packet(&self, recipient_address: &Address) -> bool {
        let recipient_bits = address_to_bits(recipient_address);
        let node_id_bits = address_to_bits(&self.id);

        if self.prefix_length == 0 {
            return true; // Store all packets
        }

        if self.prefix_length > recipient_bits.len() {
            return false;
        }

        recipient_bits[..self.prefix_length] == node_id_bits[..self.prefix_length]
    }

    /// Store a packet and notify subscribers
    async fn store_packet(&self, packet: Packet) {
        {
            let mut store = self.packet_store.lock().await;
            store.insert(packet.pow_hash.clone(), packet.clone());
        }

        // Notify subscribers about the new packet
        let subscribers = self.subscribers.lock().await;
        for subscriber in subscribers.iter() {
            let _ = subscriber.send(packet.clone());
        }
    }

    /// Forward a packet to nodes whose prefixes match the recipient address
    async fn forward_packet(&self, packet: Packet, sender_address: SocketAddr) {
        let recipient_id = packet.recipient_address;
        let recipient_bits = address_to_bits(&recipient_id);

        // Get all nodes from the routing table
        let routing_table = self.routing_table.lock().await;
        let all_nodes = routing_table.get_all_nodes();

        // Get a snapshot of node requirements
        let node_requirements = self.node_requirements.lock().await;

        let mut nodes_to_send = Vec::new();

        for node in all_nodes {
            // Skip the sender to prevent loops
            if node.address == sender_address {
                continue;
            }

            // Get the node's requirements
            if let Some(reqs) = node_requirements.get(&node.id) {
                let node_id_bits = address_to_bits(&node.id);
                let prefix_length = reqs.prefix_length.min(node_id_bits.len()).min(recipient_bits.len());

                // Check if the node's prefix matches the recipient's address
                if prefix_length > 0 && node_id_bits[..prefix_length] != recipient_bits[..prefix_length] {
                    continue; // Prefix does not match
                }

                // Check if the packet meets the node's requirements
                if packet.ttl > reqs.max_ttl || !packet.argon2_params.meets_min(&reqs.min_argon2_params) {
                    continue; // Requirements not met
                }

                nodes_to_send.push(node.clone());
            }
        }

        // Drop the lock on node_requirements
        drop(node_requirements);

        if nodes_to_send.is_empty() {
            warn!("No nodes to forward the packet with matching prefixes");
            return;
        }

        // Forward the packet to all matching nodes
        for node in nodes_to_send {
            let message = Message::Packet(packet.clone());
            self.send_message(message, node.address).await;
        }
    }

    /// Find nodes closest to a target ID (address)
    async fn find_closest_nodes(&self, target_id: &Address) -> Vec<NodeInfo> {
        let routing_table = self.routing_table.lock().await;
        routing_table.find_closest_nodes(target_id)
    }

    /// Send a message to a specific address
    async fn send_message(&self, message: Message, address: SocketAddr) {
        // Check if the IP is blacklisted
        if self.is_blacklisted(&address.ip()).await {
            warn!("Attempted to send message to blacklisted IP: {}", address);
            return;
        }

        match TcpStream::connect(address).await {
            Ok(mut stream) => {
                let data = bincode::serialize(&message).expect("Failed to serialize message");
                if let Err(e) = stream.write_all(&data).await {
                    error!("Failed to send message to {}: {:?}", address, e);
                }
            }
            Err(e) => {
                error!("Failed to connect to {}: {:?}", address, e);
            }
        }
    }

    /// Update the routing table with a new node
    pub async fn update_routing_table(&self, node_info: NodeInfo) {
        // Check if the node's IP is blacklisted
        if self.is_blacklisted(&node_info.address.ip()).await {
            warn!("Ignoring node {} due to blacklist", node_info.address);
            return;
        }

        let mut routing_table = self.routing_table.lock().await;
        routing_table.update(node_info);
    }

    async fn update_routing_table_extended(&self, node_info: NodeInfoExtended) {
        // Update routing table and store node's requirements
        self.update_routing_table(NodeInfo {
            id: node_info.id,
            address: node_info.address,
        }).await;

        // Store node's requirements in a HashMap
        let mut node_requirements = self.node_requirements.lock().await;
        node_requirements.insert(node_info.id, node_info);
    }

    fn get_node_info_extended(&self) -> NodeInfoExtended {
        NodeInfoExtended {
            id: self.id,
            address: self.address,
            prefix_length: self.prefix_length,
            pow_difficulty: self.pow_difficulty,
            max_ttl: self.max_ttl,
            min_argon2_params: self.min_argon2_params.clone(),
        }
    }

    /// Mark a node as alive in the routing table
    async fn mark_node_alive(&self, address: SocketAddr) {
        // Check if the IP is blacklisted
        if self.is_blacklisted(&address.ip()).await {
            warn!("Attempted to mark blacklisted node as alive: {}", address);
            return;
        }

        let mut routing_table = self.routing_table.lock().await;
        routing_table.mark_node_alive(address);
    }

    /// Blacklist an IP address
    async fn blacklist_ip(&self, ip: &IpAddr) {
        // Do not blacklist own IP
        if ip == &self.address.ip() {
            warn!("Attempted to blacklist own IP: {}", ip);
            return;
        }
        let mut blacklist = self.blacklist.lock().await;
        // Set a timeout for the blacklist (e.g., 10 minutes)
        let timeout = Instant::now() + self.blacklist_duration;
        blacklist.insert(*ip, timeout);

        // Remove the node from the routing table
        let mut routing_table = self.routing_table.lock().await;
        routing_table.remove_node_by_ip(ip);
        warn!("Blacklisted IP: {}", ip);
    }

    /// Check if an IP address is blacklisted (and remove if timeout has expired)
    async fn is_blacklisted(&self, ip: &IpAddr) -> bool {
        let mut blacklist = self.blacklist.lock().await;
        if let Some(&timeout) = blacklist.get(ip) {
            if Instant::now() >= timeout {
                blacklist.remove(ip);
                return false;
            }
            return true;
        }
        false
    }
}

/// Kademlia Routing Table
pub struct RoutingTable {
    pub id: NodeId,
    pub k_buckets: Vec<KBucket>,
}

pub struct KBucket {
    pub nodes: Vec<NodeInfo>,
}

impl RoutingTable {
    pub fn new(id: NodeId) -> Self {
        let mut k_buckets = Vec::new();
        for _ in 0..160 {
            k_buckets.push(KBucket::new());
        }
        RoutingTable { id, k_buckets }
    }

    fn leading_zeros_in_array(array: &[u8; 20]) -> u32 {
        let mut leading_zeros = 0;
        for &byte in array.iter() {
            let zeros = byte.leading_zeros();
            leading_zeros += zeros;
            if zeros < 8 {
                break;
            }
        }
        leading_zeros
    }

    /// Get all nodes in the routing table
    pub fn get_all_nodes(&self) -> Vec<NodeInfo> {
        let mut nodes = Vec::new();
        for bucket in &self.k_buckets {
            nodes.extend(bucket.nodes.clone());
        }
        nodes
    }

    /// Find the k closest nodes to the target ID
    pub fn find_closest_nodes(&self, target_id: &Address) -> Vec<NodeInfo> {
        let mut all_nodes = Vec::new();

        let target_id = *target_id;
        let distance = xor_distance(&self.id, &target_id);
        let bucket_index = Self::leading_zeros_in_array(&distance) as usize;

        // Collect nodes from the closest k-buckets
        for i in bucket_index..self.k_buckets.len() {
            all_nodes.extend(self.k_buckets[i].nodes.clone());
        }

        for i in (0..bucket_index).rev() {
            all_nodes.extend(self.k_buckets[i].nodes.clone());
        }

        // Sort nodes by XOR distance to target ID
        all_nodes.sort_by_key(|node| xor_distance(&node.id, &target_id));

        all_nodes.truncate(K); // Return up to K nodes
        all_nodes
    }

    /// Update the routing table with a new node
    pub fn update(&mut self, node_info: NodeInfo) {
        let distance = xor_distance(&self.id, &node_info.id);
        let bucket_index = Self::leading_zeros_in_array(&distance) as usize;

        if bucket_index >= self.k_buckets.len() {
            return; // Ignore nodes that are too far
        }

        let bucket = &mut self.k_buckets[bucket_index];

        // Check if the node is already in the bucket
        if let Some(pos) = bucket.nodes.iter().position(|n| n.id == node_info.id) {
            // Move the node to the end to mark it as recently seen
            let node = bucket.nodes.remove(pos);
            bucket.nodes.push(node);
        } else {
            if bucket.nodes.len() < K {
                bucket.nodes.push(node_info);
            } else {
                // Bucket is full; implement replacement policies if needed
                // For simplicity, we'll replace the least recently seen node
                bucket.nodes.remove(0);
                bucket.nodes.push(node_info);
            }
        }
    }

    /// Remove a node by IP address from the routing table
    pub fn remove_node_by_ip(&mut self, ip: &IpAddr) {
        for bucket in &mut self.k_buckets {
            bucket.nodes.retain(|n| &n.address.ip() != ip);
        }
    }

    /// Mark a node as alive
    pub fn mark_node_alive(&mut self, address: SocketAddr) {
        for bucket in &mut self.k_buckets {
            if let Some(pos) = bucket.nodes.iter().position(|n| n.address == address) {
                // Move the node to the end to mark it as recently seen
                let node = bucket.nodes.remove(pos);
                bucket.nodes.push(node);
                return;
            }
        }
    }
}

impl KBucket {
    pub fn new() -> Self {
        KBucket { nodes: Vec::new() }
    }
}

/// The maximum number of nodes per k-bucket (k)
const K: usize = 20;

/// Generates a node ID by hashing the node's public key
fn generate_node_id(public_key: &[u8]) -> NodeId {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let result = hasher.finalize();
    let mut id = [0u8; 20];
    id.copy_from_slice(&result[..20]);
    id
}

/// Calculates the XOR distance between two node IDs
fn xor_distance(a: &NodeId, b: &NodeId) -> NodeId {
    let mut distance = [0u8; 20];
    for i in 0..20 {
        distance[i] = a[i] ^ b[i];
    }
    distance
}

/// Converts an Address to a bit vector
fn address_to_bits(address: &Address) -> Vec<bool> {
    let mut bits = Vec::with_capacity(ADDRESS_LENGTH * 8);
    for byte in address.iter() {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}
