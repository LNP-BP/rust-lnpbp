# LNP/BP Core Library

![Build](https://github.com/LNP-BP/rust-lnpbp/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/rust-lnpbp/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/rust-lnpbp/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/LNP-BP/rust-lnpbp/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/rust-lnpbp)

[![crates.io](https://img.shields.io/crates/v/lnpbp)](https://crates.io/crates/lnpbp)
[![Docs](https://docs.rs/lnpbp/badge.svg)](https://docs.rs/lnpbp)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

This is LNP/BP Core Library: a rust library implementing LNP/BP specifications 
<https://github.com/LNP-BP/LNPBPs>. It can be used to simplify development of
layer 2 & 3 solutions on top of Lightning Network and Bitcoin blockchain. 

The current list of the projects based on the library include:
* [RGB](https://github.com/rgb-org/rgb-core): Confidential & scalable smart 
  contracts for Bitcoin & Lightning
* [Generalized Lightning Network](https://www.youtube.com/watch?v=YmmNsWS5wiM) 
  and it's reference implementation named 
  [LNP node](https://github.com/LNP-BP/lnp-node) enabling:
* [LNP](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/LNP%20Networking%20%26%20RGB%20Integration_final.pdf): 
  Networking protocol for privacy-keeping and censorship-resistant applications,
  operating in both P2P and RPC modes (currently used as a part of Lightning 
  network, but our effort is to make it more generic and usable even outside of 
  LN). All services, developed by LNP/BP Standards Association (see points
  below) are made with LNP.
  - RGB extensions
  - DLC extensions
  - [Lightspeed payments](https://github.com/LNP-BP/LNPBPs/issues/24)
  - Multi-peer channels
  - Faster lightning experiments (quicker adoption of eltoo, Taproot etc)
* [BP node](https://github.com/LNP-BP/bp-node): Indexing service for bitcoin 
  blockchain; more efficient & universal Electrum server replacement. In 
  perspective - validating Bitcoin network node (using libbitcoinconsus)

Potentially, with LNP/BP Core library you can simplify the development of
* Discreet log contracts
* Implement experimental lightning features
* Do complex multi-threaded or elastic/dockerized client-service microservice 
  architectures

To learn more about the technologies enabled by the library please check:
* [RGB Technology Internals](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/)
* [Networking with LNP](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/LNP%20Networking%20%26%20RGB%20Integration_final.pdf)
* [LNP/BP Nodes Initiative](https://github.com/LNP-BP/FAQ/blob/master/Presentation%20slides/LNP-BP%20Nodes%20Initiative.pdf)

The development of the library projects is supported by LNP/BP Standards 
Association.

## Install

### Clone and compile library

Minimum supported rust compiler version (MSRV): 1.47 (caused by array size
limitation to 32 bytes only in `strict_encoding` crate).

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

