# RustBitmessage

A Rust implementation of [PyBitmessage](https://github.com/Bitmessage/PyBitmessage) with security and efficiency improvements. This project also integrates suggestions from [A Very Technical Look at Bitmessage](https://zolagonano.github.io/blog/posts/a-very-technical-look-at-bitmessage) and aims to implement prefix filtering for enhanced scalability.

## Overview

RustBitmessage is designed to be a more secure and efficient version of Bitmessage, a decentralized communication protocol known for its emphasis on privacy and resistance to surveillance. By reimagining the protocol in Rust, we leverage Rust’s safety guarantees and modern features to provide a robust implementation with enhanced performance.

### Key Improvements

- **Security**: Updates and improvements to encryption methods.
- **Efficiency**: Optimizations for memory and compute requirements.
- **Scalability**: Integration of prefix filtering as outlined in [this proposal](https://wiki.bitmessage.org/index.php/Scalability_through_Prefix_Filtering) to reduce resource usage across nodes.

## Features

This implementation includes several planned features to enhance the functionality of Bitmessage.

### Planned Features (TODO)

- **Address Broadcasting**: Enabling nodes to broadcast their address and keys to other nodes.
- **Key Retrieval**: Allowing nodes to request public keys from specific addresses.
- **Acknowledgment of Messages**: Implementing acknowledgments to ensure message delivery.
- **Node Blacklisting**: If node A is blacklisted for node B, node B refuses any connections from that IP.
- **Integration testing**: More tests for node discovery
- **Weakness Analysis**: What are the flaws in the protocol? From network analysis, you could associate a sender address / keys with an IP address. If everyone uses different sender/receiver addresses, the problem is mitigated. You can possibly pinpoint sources accurately but not destination IPs. How strong is the encryption/authentication? How disruptable is the network?
- **Group Messaging**: Bitmessage group messaging?
- **TOR-type routing**: Could you bounce a message through TOR before hitting the target node(s)? This would obscure the source IP to some reasonably strong degree.
- **Node Prefix-Based Forwarding**: Only propagate to nodes with prefix matching message
- **Node TTL Capping**: Rather than discarding messages w/ ttl too long
- **Node Prefix Adjustments**: Nodes can move up and down prefix levels by choice (shorter prefix hosts more messages), if a node can't see the other prefix at or above its level (so 011 nodeshould be able to see a 010 or a 01 node), it should move up a level (in this case, to 01, to host those messages). Nodes should be able to refuse any message relays that aren't for its prefix, and blacklist on that basis. A node should always help you discover other nodes though. The peer database should have some convenient prefix listing or be in a hash map (prefix): nodes serving that prefix. A node should broadcast changes in its own prefix.
- **Node traffic analysis**: Help node decide what prefix level to set.

### Scalability and Filtering

To support a growing network, we aim to integrate prefix filtering. This approach will allow nodes to reduce unnecessary message processing, making RustBitmessage scalable for larger networks.

## Dependencies and Acknowledgments

RustBitmessage relies on several external libraries for its functionality:

- **[`rspow`](https://github.com/zolagonano/rspow)**: A Rust library for proof-of-work using Argon2id. We use `rspow` for implementing the proof-of-work mechanism in our protocol.
- **[`rust-argon2`](https://github.com/sru-systems/rust-argon2)**: A Rust implementation of the Argon2 password hashing function. We use `rust-argon2` within `rspow` for the proof-of-work calculations.

We are grateful to the developers of these libraries for their work, which has significantly contributed to the development of RustBitmessage.

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/) programming language and toolchain.

### Building the Project

1. Clone this repository:

   ```bash
   git clone https://github.com/razor389/bitmessage-rust.git
   cd bitmessage-rust
   ```

2. Build the project:

   ```bash
   cargo build --release
   ```

3. Run tests to ensure everything is functioning:

   ```bash
   cargo test
   ```

## Usage

Instructions for running and using RustBitmessage will be added as development progresses.

## License

This project is licensed under the MIT License. For more details, please see the [`LICENSE`](./LICENSE) file.

### Third-Party Licenses

- **`rspow`**: Licensed under the MIT License. See the [rspow repository](https://github.com/zolagonano/rspow) for details.
- **`rust-argon2`**: Dual-licensed under the MIT or Apache-2.0 License. See the [rust-argon2 repository](https://github.com/sru-systems/rust-argon2) for details.

Please ensure compliance with all applicable licenses when using this software.

