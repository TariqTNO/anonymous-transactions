# Anonymous Transactions using zk-SNARKs
This repository contains a proof-of-concept implementation of a decentralized anonymous transaction scheme using 
zk-SNARKs that finds a balance between privacy and auditability.

## Usage
To compile this code we assume that the most recent version of Rust stable is installed.
Compilation can be done using:
```
$ cargo build --release
```

Compilation will generate two binaries `demo_server` and `demo_client` that can be run respectively by:
```
$ cargo run --bin demo_server --release
```
and
```
$ cargo run --bin demo_client --release
```

One should run exactly one server and at least one client.

First time startup of either client or server generates zk-SNARK proof parameters that will be stored for future calls. 
This might take up quite some time, but only needs to be done once. We advise first starting the server and waiting for 
the parameter generation be completed and only then start clients. After a first time run, the order is not relevant any 
longer.

Each client and the server will present a list of commands with explanations. The client commands can be used to create 
transactions and retrieve the most recent status of the blockchain. The server commands can be used to generate new 
blocks and view the current blockchain status.
