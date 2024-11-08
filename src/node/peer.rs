// src/peer.rs

use crate::common::{Message, HandshakeInfo};
use crate::node::Node;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, Notify};
use std::sync::Arc;
use std::net::SocketAddr;
use log::{error, info};
use bincode;

#[derive(Clone)]
pub struct Peer {
    pub id: usize,
    pub reader: Arc<Mutex<OwnedReadHalf>>,
    pub writer: Arc<Mutex<OwnedWriteHalf>>,
    pub address: Arc<Mutex<Option<SocketAddr>>>, // Changed to Arc<Mutex<Option<SocketAddr>>>
    pub handshake_info: Arc<Mutex<Option<HandshakeInfo>>>,
    pub shutdown: Arc<Notify>,
}

impl Peer {
    pub async fn new(socket: TcpStream, address: Option<SocketAddr>) -> tokio::io::Result<Self> {
        let id = generate_unique_id();
        let peer_address = if let Some(addr) = address {
            Some(addr)
        } else {
            socket.peer_addr().ok()
        };
        let (read_half, write_half) = socket.into_split();
        let peer = Peer {
            id,
            reader: Arc::new(Mutex::new(read_half)),
            writer: Arc::new(Mutex::new(write_half)),
            address: Arc::new(Mutex::new(peer_address)), // Initialize with Arc<Mutex>
            handshake_info: Arc::new(Mutex::new(None)),
            shutdown: Arc::new(Notify::new()),
        };
        Ok(peer)
    }

    pub async fn update_address(&self, new_address: SocketAddr) {
        let mut addr = self.address.lock().await;
        *addr = Some(new_address);
        info!("Peer {} address updated to {}", self.id, new_address);
    }

    /// Gracefully shutdown the peer connection
    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    pub async fn send_message(&self, message: &Message) -> tokio::io::Result<()> {
        let data = bincode::serialize(message).map_err(|e| {
            error!("Failed to serialize message: {:?}", e);
            tokio::io::Error::new(tokio::io::ErrorKind::Other, e)
        })?;
        let length = (data.len() as u32).to_be_bytes();
        let mut writer = self.writer.lock().await;
        writer.write_all(&length).await?;
        writer.write_all(&data).await?;
        Ok(())
    }

    /// Reads a complete message based on the length prefix
    async fn read_message(&self) -> Result<Message, tokio::io::Error> {
        // Step 1: Read exactly 4 bytes for the length prefix
        let mut length_bytes = [0u8; 4];
        {
            let mut reader = self.reader.lock().await;
            reader.read_exact(&mut length_bytes).await?;
        }
        let length = u32::from_be_bytes(length_bytes) as usize;

        // Step 2: Read exactly `length` bytes for the message
        let mut data = vec![0u8; length];
        {
            let mut reader = self.reader.lock().await;
            reader.read_exact(&mut data).await?;
        }

        // Step 3: Deserialize the message
        let message: Message = bincode::deserialize(&data).map_err(|e| {
            error!("Failed to deserialize message from peer {}: {:?}", self.id, e);
            tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, e)
        })?;

        Ok(message)
    }

    pub async fn receive_packets(self: Arc<Self>, node: Arc<Node>) {
        loop {
            tokio::select! {
                _ = self.shutdown.notified() => {
                    info!("Shutting down connection with peer {}", self.id);
                    // Attempt to shutdown the writer
                    let mut writer = self.writer.lock().await;
                    if let Err(e) = writer.shutdown().await {
                        error!("Error shutting down writer for peer {}: {:?}", self.id, e);
                    }
                    break;
                }
                result = self.read_message() => { // Correct: No `.await` here
                    match result {
                        Ok(message) => {
                            match message {
                                Message::Packet(packet) => {
                                    let node_clone = Arc::clone(&node);
                                    let peer_id = self.id;
                                    tokio::spawn(async move {
                                        node_clone.receive_packet(packet, Some(peer_id)).await;
                                    });
                                }
                                Message::KnownNodes(addresses) => {
                                    let node_clone = Arc::clone(&node);
                                    tokio::spawn(async move {
                                        node_clone.update_known_nodes(addresses).await;
                                    });
                                }
                                Message::RequestAllMessages => {
                                    let node_clone = Arc::clone(&node);
                                    let peer_clone = Arc::clone(&self);
                                    tokio::spawn(async move {
                                        let packets = node_clone.get_all_messages().await;
                                        let response = Message::MessagesResponse(packets);
                                        if let Err(e) = peer_clone.send_message(&response).await {
                                            error!("Failed to send messages to peer {}: {:?}", peer_clone.id, e);
                                        }
                                    });
                                }
                                Message::Handshake(handshake) => {
                                    // Store the handshake information
                                    {
                                        let mut handshake_info = self.handshake_info.lock().await;
                                        *handshake_info = Some(handshake.clone());
                                    }

                                    info!("Received handshake from peer {}: {:?}", self.id, handshake);

                                    // Handle the handshake in the node
                                    let node_clone = Arc::clone(&node);
                                    let peer_clone = Arc::clone(&self);
                                    tokio::spawn(async move {
                                        node_clone.handle_handshake(peer_clone, handshake).await;
                                    });
                                }
                                _ => {
                                    error!("Unexpected message type from peer {}", self.id);
                                }
                            }
                        }
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                info!("Connection closed by peer {}", self.id);
                            } else {
                                error!("Error reading from peer {}: {:?}", self.id, e);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    pub async fn send_known_nodes(&self, nodes: &Vec<SocketAddr>) -> tokio::io::Result<()> {
        let message = Message::KnownNodes(nodes.clone());
        self.send_message(&message).await
    }
}

fn generate_unique_id() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static ID_COUNTER: AtomicUsize = AtomicUsize::new(1);
    ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}
