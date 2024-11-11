// src/main.rs

use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use bitmessage_rust::node::Node;
use bitmessage_rust::client::Client;
use bitmessage_rust::authentication::Authentication;
use bitmessage_rust::encryption::Encryption;
use bitmessage_rust::serializable_argon2_params::SerializableArgon2Params;
use argon2::Params as Argon2Params;
use log::{info, error};

#[derive(Parser)]
#[command(name = "Bitmessage")]
struct Cli {
    #[arg(long)]
    node: bool,
    #[arg(long)]
    client: bool,
    #[arg(long)]
    address: Option<String>,
    #[arg(long)]
    connect: Vec<String>,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Cli::parse();

    if args.node {
        let address_str = args.address.clone().expect("Node address is required");
        let address: SocketAddr = address_str.parse().expect("Invalid address");

        let pow_difficulty = 1;
        let max_ttl = 3600;
        let argon2_params = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params = SerializableArgon2Params::from_argon2_params(&argon2_params);

        // Use an empty prefix or compute based on criteria
        let prefix = vec![]; // Adjust as needed

        // Since `Node::new` now returns `Arc<Node>`, we don't need to wrap it again
        let node = Node::new(
            generate_unique_id(),
            prefix,
            pow_difficulty,
            max_ttl,
            serializable_params.clone(),
            address,
        ).await;

        // Connect to other nodes
        for addr_str in args.connect {
            let addr: SocketAddr = addr_str.parse().expect("Invalid address");
            if let Err(e) = node.connect_sender.send(addr).await {
                error!("Failed to send address {} to connection queue: {:?}", addr, e);
            }
        }

        // Start gossiping
        node.start_gossip();

        // Run the node
        let node_clone = Arc::clone(&node);
        tokio::spawn(async move {
            if let Err(e) = node_clone.run().await {
                error!("Node failed: {:?}", e);
            }
        });
    }

    if args.client {
        let node_address_str = args.address.expect("Node address is required for client");
        let node_address: SocketAddr = node_address_str.parse().expect("Invalid address");

        let client = Client::new(
            Authentication::new(),
            Encryption::new(),
            node_address,
        );

        // For demonstration, client sends a message to itself
        let message = b"Hello, ShadowLink!";
        let pow_difficulty = 1;
        let ttl = 3600;
        let argon2_params = Argon2Params::new(1024, 1, 1, Some(32)).unwrap();
        let serializable_params = SerializableArgon2Params::from_argon2_params(&argon2_params);

        client.send_message(
            &client.auth.verifying_key(),
            &client.encryption.permanent_public_key,
            message,
            pow_difficulty,
            ttl,
            serializable_params,
        ).await;

        // Implement receiving messages as needed
        let received_messages = client.receive_messages(pow_difficulty).await;
        for msg in received_messages {
            info!("Client received message: {:?}", String::from_utf8_lossy(&msg));
        }
    }

    // Keep the main thread alive if necessary
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}

fn generate_unique_id() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static ID_COUNTER: AtomicUsize = AtomicUsize::new(1);
    ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}
