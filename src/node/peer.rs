use crate::packet::Packet;
use crate::node::Node;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{ OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use std::sync::Arc;
use std::net::SocketAddr;
use log::error;
use serde::{Serialize, Deserialize};
use bincode;

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    Packet(Packet),
    KnownNodes(Vec<SocketAddr>),
    RequestAllMessages,
    MessagesResponse(Vec<Packet>),
}

#[derive(Clone)]
pub struct Peer {
    pub id: usize,
    pub reader: Arc<Mutex<OwnedReadHalf>>,
    pub writer: Arc<Mutex<OwnedWriteHalf>>,
    pub address: Option<SocketAddr>,
}

impl Peer {
    pub async fn new(socket: TcpStream, address: Option<SocketAddr>) -> tokio::io::Result<Self> {
        let id = generate_unique_id();
        let (read_half, write_half) = socket.into_split();
        let peer = Peer {
            id,
            reader: Arc::new(Mutex::new(read_half)),
            writer: Arc::new(Mutex::new(write_half)),
            address,
        };
        Ok(peer)
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

    pub async fn receive_packets(self: Arc<Self>, node: Arc<Node>) {
        loop {
            let mut reader = self.reader.lock().await;

            // Read the length of the incoming message
            let mut length_bytes = [0u8; 4];
            match reader.read_exact(&mut length_bytes).await {
                Ok(_) => {}
                Err(e) => {
                    error!("Error reading from peer {}: {:?}", self.id, e);
                    break;
                }
            }
            let length = u32::from_be_bytes(length_bytes) as usize;

            // Read the message data
            let mut data = vec![0u8; length];
            match reader.read_exact(&mut data).await {
                Ok(_) => {}
                Err(e) => {
                    error!("Error reading from peer {}: {:?}", self.id, e);
                    break;
                }
            }

            drop(reader); // Release the lock before processing the message

            // Deserialize the message
            let message: Message = match bincode::deserialize(&data) {
                Ok(msg) => msg,
                Err(e) => {
                    error!("Failed to deserialize message from peer {}: {:?}", self.id, e);
                    continue;
                }
            };

            // Process the message
            match message {
                Message::Packet(packet) => {
                    let node_clone = Arc::clone(&node);
                    let peer_id = self.id; // Capture `self.id`
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
                _ => {
                    error!("Unexpected message type from peer {}", self.id);
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
