# RustBitmessage

A Rust implementation of [PyBitmessage](https://github.com/Bitmessage/PyBitmessage) with security and efficiency improvements. This project also integrates suggestions from [A Very Technical Look at Bitmessage](https://zolagonano.github.io/blog/posts/a-very-technical-look-at-bitmessage) and aims to implement prefix filtering for enhanced scalability.

## Overview

RustBitmessage is designed to be a more secure and efficient version of Bitmessage, a decentralized communication protocol known for its emphasis on privacy and resistance to surveillance. By reimagining the protocol in Rust, we leverage Rust’s safety guarantees and modern features to provide a robust implementation with enhanced performance.

### Key Improvements

- **Security**: Updates and improvements to encryption methods
- **Efficiency**: Optimizations for memory and compute requirements
- **Scalability**: Integration of prefix filtering as outlined in [this proposal](https://wiki.bitmessage.org/index.php/Scalability_through_Prefix_Filtering) to reduce resource usage across nodes

## Features

This implementation includes several planned features to enhance the functionality of Bitmessage. 

### Planned Features (TODO)


- **Client Anonymity**: Clients should look like nodes to the nodes they are communicating with (so they aren't obviously the origin of the messages they send)
- **POW Check in Node**: Received messages should have POW verified. No network traffic should propagate without POW. Any node forwarding non POW traffic must be blacklisted.
- **Message Compression**: Reducing the message size for efficient storage and transmission.
- **Address Broadcasting**: Enabling nodes to broadcast their address and keys to other nodes.
- **Key Retrieval**: Allowing nodes to request public keys from specific addresses.
- **Node Connectivity**: Running nodes with IP and port bindings for network communication.
- **Message Timestamping**: Adding timestamps to messages for tracking and validation.
- **Message TTL**: Setting a time-to-live (TTL) for messages to expire outdated information.
- **Acknowledgment of Messages**: Implementing acknowledgments to ensure message delivery.
- **Node Communication**: Facilitating reliable communication between nodes, maintaining node lists/hashmaps to rout messages efficiently.
- **Node Blacklisting**: Adding the ability to blacklist malicious or non-cooperative nodes.

### Scalability and Filtering

To support a growing network, we aim to integrate prefix filtering. This approach will allow nodes to reduce unnecessary message processing, making RustBitmessage scalable for larger networks.

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/) programming language and toolchain

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

This project is licensed under the MIT License. For more details, please see the `LICENSE` file.

