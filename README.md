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

- **Client Anonymity**: Clients should look like nodes to the nodes they are communicating with (so they aren't obviously the origin of the messages they send).
- **Message Compression**: Reducing the message size for efficient storage and transmission.
- **Address Broadcasting**: Enabling nodes to broadcast their address and keys to other nodes.
- **Key Retrieval**: Allowing nodes to request public keys from specific addresses.
- **Node Connectivity**: Running nodes with IP and port bindings for network communication.
- **Acknowledgment of Messages**: Implementing acknowledgments to ensure message delivery.
- **Node Communication**: Facilitating reliable communication between nodes, maintaining node lists/hashmaps to route messages efficiently.
- **PoW Parameters**: Allow clients to adjust the memory/core allocation for Argon2id; clients should be able to set parameters.

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

