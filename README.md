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

- **Timeouts**: Implement timeouts on read operations
- **Network Connectivity**: Nodes should periodically ping one another in a lightweight way to stay active. Otherwise go into an inactive node list.
- **Acknowledgment of Messages**: Implementing optional acknowledgments to ensure message delivery.
- **Integration Testing**: Adequate tests for every function
- **Weakness Analysis**: Identifying flaws in the protocol, including the potential for associating sender addresses with IPs.
- **Group Messaging**: Bitmessage group messaging.
- **TOR-type Routing**: Bouncing a message through intermediate nodes before hitting the target node to obscure the source IP.
- **Node Prefix-Based Forwarding**: Propagating messages only to nodes with matching prefixes.
- **Node Prefix Adjustments**: Dynamic prefix adjustments based on node traffic analysis and peer node visibility
- **Node Traffic Analysis**: Helping nodes decide their optimal prefix level.

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

RustBitmessage can be used in either **node mode** or **client mode**. 

### Running as a Node

A **node** operates within the Bitmessage network, performing tasks such as connecting to peers, broadcasting messages, and forwarding messages.

1. **Run the Node**: Use the `--node` flag along with the `--address` flag to specify the node’s IP and port, and the `--connect` flag to connect to other nodes.

   ```bash
   cargo run --release -- --node --address "127.0.0.1:12345" --connect "127.0.0.1:12346"
   ```

   - **`--node`**: Starts the Bitmessage node.
   - **`--address`**: Required. Specifies the node’s IP address and port.
   - **`--connect`**: Optional. Connects to one or more specified nodes. Add additional addresses with space-separated values.

2. **Running and Gossiping**: The node automatically begins running and will attempt to connect to the specified addresses for message gossiping.

### Running as a Client

A **client** interacts with a Bitmessage node, sending and receiving messages.

1. **Run the Client**: Use the `--client` flag along with the `--address` flag to specify the node address to connect to.

   ```bash
   cargo run --release -- --client --address "127.0.0.1:12345"
   ```

   - **`--client`**: Starts the Bitmessage client.
   - **`--address`**: Required. Specifies the node’s IP address and port.

2. **Sending Messages**: The client sends a message (for testing, it sends "Hello, Bitmessage!") to itself. This demonstrates basic message transmission.

3. **Receiving Messages**: The client listens for messages from the node, displaying any received messages in the console.

### Keep the Node Running

To keep the node or client running without interruptions, the program includes a loop that keeps the main thread active.

## Logging Configuration

To view log output in your terminal, you can set the log level using the `RUST_LOG` environment variable.

### Setting Log Levels in Bash

For **Bash** (Linux, macOS, or WSL on Windows):

```bash
export RUST_LOG=info
```

This will set the log level to `info`. Replace `info` with `debug` or `error` as needed. You can then run the program or tests, and logs will appear in the output.

### Setting Log Levels in PowerShell

For **PowerShell** (Windows):

```powershell
$env:RUST_LOG="info"
```

Replace `"info"` with the desired log level, such as `"debug"` or `"error"`.

### Viewing Logs in Test Output

When running tests, log output is captured by default. To view logs during test runs, use the `-- --nocapture` flag:

```bash
cargo test -- --nocapture
```

This will display log output in the console, making it easier to debug test cases.

## License

This project is licensed under the MIT License. For more details, please see the [`LICENSE`](./LICENSE) file.

### Third-Party Licenses

- **`rspow`**: Licensed under the MIT License. See the [rspow repository](https://github.com/zolagonano/rspow) for details.
- **`rust-argon2`**: Dual-licensed under the MIT or Apache-2.0 License. See the [rust-argon2 repository](https://github.com/sru-systems/rust-argon2) for details.

Please ensure compliance with all applicable licenses when using this software.