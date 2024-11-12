// src/main.rs

use clap::Parser;
use std::{net::SocketAddr, time::Duration};

use bitmessage_rust::node::Node;
use bitmessage_rust::client::Client;
use bitmessage_rust::authentication::Authentication;
use bitmessage_rust::encryption::Encryption;
use bitmessage_rust::serializable_argon2_params::SerializableArgon2Params;
use argon2::Params as Argon2Params;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

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

    #[arg(long, default_value_t = 4)]
    prefix_length: usize,

    #[arg(long, default_value_t = 1)]
    pow_difficulty: usize,

    // New arguments for max_ttl and min_argon2_params
    #[arg(long, default_value_t = 86400)]
    max_ttl: u64, // Maximum TTL in seconds (default: 24 hours)

    #[arg(long, default_value_t = 4096)]
    min_m_cost: u32, // Minimum memory cost for Argon2

    #[arg(long, default_value_t = 3)]
    min_t_cost: u32, // Minimum time cost for Argon2

    #[arg(long, default_value_t = 1)]
    min_p_cost: u32, // Minimum parallelism for Argon2

    #[arg(long, default_value_t = 32)]
    min_output_length: usize, // Minimum output length for Argon2
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Cli::parse();

    if args.node {
        let address_str = args.address.clone().expect("Node address is required");
        let address: SocketAddr = address_str.parse().expect("Invalid address");

        let pow_difficulty = args.pow_difficulty;
        let prefix_length = args.prefix_length;

        // New parameters
        let max_ttl = args.max_ttl;
        let min_argon2_params = SerializableArgon2Params {
            m_cost: args.min_m_cost,
            t_cost: args.min_t_cost,
            p_cost: args.min_p_cost,
            output_length: Some(args.min_output_length),
        };

        // Generate a new signing key for the node (for demonstration purposes)
        let mut csprng = OsRng {};
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();

        // Create the node
        let node = Node::new(
            &public_key_bytes,
            address,
            prefix_length,
            pow_difficulty,
            max_ttl, // Pass max_ttl
            min_argon2_params, // Pass min_argon2_params
            Duration::new(60, 0),
            Duration::new(60, 0),
        )
        .await;

        // Connect to other nodes
        for addr_str in args.connect {
            let addr: SocketAddr = addr_str.parse().expect("Invalid address");
            let node_info = bitmessage_rust::common::NodeInfo {
                id: [0u8; 20], // For initial connection, ID can be empty or fetched via handshake
                address: addr,
            };
            node.update_routing_table(node_info).await;
        }

        // Note: `Node::new` already spawns `node.run()` via `tokio::spawn`
        // Therefore, you don't need to call `node.run().await` here
        // Removing `node.run().await` to prevent blocking

        // Uncomment the following line if you intend to keep the main task alive
        // Otherwise, the program may exit immediately after spawning the node
        // tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
    }

    if args.client {
        let node_address_str = args.address.expect("Node address is required for client");
        let node_address: SocketAddr = node_address_str.parse().expect("Invalid address");

        let auth = Authentication::new();
        let encryption = Encryption::new();

        let client = Client::new(
            auth,
            encryption,
            node_address,
        );

        // For demonstration, client sends a message to itself
        let message = b"Hello, ShadowLink!";
        let pow_difficulty = args.pow_difficulty;

        // Set TTL (must be <= node's max_ttl)
        let ttl = args.max_ttl; // Use the same max_ttl as node to ensure acceptance

        // Set Argon2 parameters (must meet or exceed node's min_argon2_params)
        let argon2_params = Argon2Params::new(
            args.min_m_cost, // m_cost
            args.min_t_cost, // t_cost
            args.min_p_cost, // p_cost
            Some(args.min_output_length), // output_length
        ).unwrap();

        let serializable_params = SerializableArgon2Params::from_argon2_params(&argon2_params);

        // Send a message to self
        client
            .send_message(
                &client.auth.verifying_key(),
                &client.encryption.permanent_public_key,
                message,
                pow_difficulty,
                ttl,
                serializable_params.clone(),
            )
            .await;

        // Subscribe to the node and receive messages
        client.subscribe_and_receive_messages(pow_difficulty).await;
    }
}
