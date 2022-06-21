# ID-based self-encryption schema

## Overview
The prototype of ID-based self-encryption schema implemented in Rust and compiled into WebAssembly as part of the Delft University of Technology Bachelor's Thesis.

The original paper: http://resolver.tudelft.nl/uuid:77406422-688c-4158-93f1-a83ab97810b4

This source code is based on MaidSafe's self-encryption library, https://github.com/maidsafe/self_encryption  

Hyperledger Fabric application: https://github.com/ilyagrishkov/ib-self-encryption  
Smart contract: https://github.com/ilyagrishkov/ib-self-encryption-smart-contract

## Installation
* Rust v1.60.0

## Run

#### Clone the repository
```shell
git clone https://github.com/ilyagrishkov/ib-self-encryption-rust.git
```

#### Navigate to the application directory
```shell
cd ib-self-encryption-rust
```

#### Add wasm32-wasi compilation target
```shell
rustup target add wasm32-wasi
```

#### Build WASM library
```shell
cargo build --target wasm32-wasi
```
