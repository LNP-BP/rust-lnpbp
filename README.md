# LNP/BP Library

![Build](https://github.com/LNP-BP/rust-lnpbp/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/rust-lnpbp/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/rust-lnpbp/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/LNP-BP/rust-lnpbp/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/rust-lnpbp)

[![crates.io](https://img.shields.io/crates/v/lnpbp)](https://crates.io/crates/lnpbp)
[![Docs](https://docs.rs/lnpbp/badge.svg)](https://docs.rs/lnpbp)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

The repository represents a set of libraries implementing LNP/BP specifications 
<https://github.com/LNP-BP/LNPBPs> not fitting into a scope of other existing 
LNP/BP core libraries (client-side-validation, BP, LNP, RGB, invoicing). It can 
be used to simplify development of layer 2 & 3 solutions on top of Lightning 
Network and Bitcoin blockchain.

Currently, the repository contains the following crates:
- `lnpbp_bech32`: library implementing LNPBP-14 standard of Bech32 encoding for
  client-side-validated data.
- `lnpbp_chain`: library providing chain parameters for bitcoin-related 
  blockchains;
- `lnpbp_elgamal`: library implementing LNPBP-31 standard for ElGamal encryption 
  using Secp256k1 curve;
- LNPBP umbrella crate containing all aforementioned libraries.

Other libraries, implementing LNP/BP specifications, not included in this crate:
- Client-side-validation foundation libraries
  ([`client_side_validation`](https://github.com/LNP-BP/client_side_validation))
- Bitcoin protocol core library 
  ([`bp-core`](https://github.com/LNP-BP/bp-core))
- Lightning network protocol core library
  ([`lnp-core`](https://github.com/LNP-BP/lnp-core))
- RGB core library implementing confidential & scalable smart contracts for 
  Bitcoin & Lightning ([`rgb-core`](https://github.com/rgb-org/rgb-core))
- [Universal invoicing library](https://github.com/LNP-BP/invoices)

The current list of the projects based on these libraries include:
* [RGB Node](https://github.com/rgb-org/rgb-node)
* [LNP Node](https://github.com/LNP-BP/lnp-node) enabling:
  - RGB extensions
  - DLC extensions
  - [Lightspeed payments](https://github.com/LNP-BP/LNPBPs/issues/24)
  - Multi-peer channels
  - Faster lightning experiments (quicker adoption of eltoo, Taproot etc)
* [BP Node](https://github.com/LNP-BP/bp-node): Indexing service for bitcoin 
  blockchain; more efficient & universal Electrum server replacement. In 
  perspective - validating Bitcoin network node (using libbitcoinconsus)

Potentially, with LNP/BP libraries you can simplify the development of
* Discreet log contracts
* Implement experimental lightning features
* Do complex multi-threaded or elastic/dockerized client-service microservice 
  architectures

The development of the libraries is supported by LNP/BP Standards Association.

## Install

### Clone and compile library

Minimum supported rust compiler version (MSRV): 1.59.0.

```shell script
git clone https://github.com/lnp-bp/rust-lnpbp
cd rust-lnpbp
cargo build --release --all-features
```

The library can be found in `target/release` directory.

You can run full test suite with:

```shell
cargo test --workspace --all-features
```

Please refer to the [`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) 
for more detailed instructions. 

### Use library in other projects

Add these lines to your `Cargo.toml` file at the very end of the `[dependecies]`
section:

```toml
lnpbp = "~0.5.0"
lnpbp_bech32 = "~0.5.0"
lnpbp_chain = "~0.5.0"
lnpbp_elgamal = "~0.5.0"
```


## Contributing

Contribution guidelines can be found in a separate 
[CONTRIBUTING](CONTRIBUTING.md) file


## More information

### Policy on Altcoins/Altchains

Altcoins and "blockchains" other than Bitcoin blockchain/Bitcoin protocols are 
not supported and not planned to be supported; pull requests targeting them will 
be declined.

### Licensing

See [LICENCE](./LICENSE) file.

