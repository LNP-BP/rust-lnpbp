// LNP/BP lLibraries implementing LNPBP specifications & standards
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! Umbrella crate for a set of libraries implementing LNP/BP specifications
//! <https://github.com/LNP-BP/LNPBPs> not fitting into a scope of other existing
//! LNP/BP core libraries (client-side-validation, BP, LNP, RGB, invoicing). It
//! can be used to simplify development of layer 2 & 3 solutions on top of
//! Lightning Network and Bitcoin blockchain.
//!
//! Currently, the repository contains the following crates:
//! - [`lnpbp_bech32`]: library implementing LNPBP-14 standard of Bech32
//!   encoding for client-side-validated data.
//! - [`lnpbp_chain`]: library providing chain parameters for bitcoin-related
//!   blockchains;
//! - [`lnpbp_elgamal`]: library implementing LNPBP-31 standard for ElGamal
//!   encryption using Secp256k1 curve;
//!
//! Other libraries, implementing LNP/BP specifications, not included in this
//! crate:
//! - Client-side-validation foundation libraries ([`client_side_validation`](https://github.com/LNP-BP/client_side_validation))
//! - Bitcoin protocol core library ([`bp-core`](https://github.com/LNP-BP/bp-core))
//! - Lightning network protocol core library ([`lnp-core`](https://github.com/LNP-BP/lnp-core))
//! - RGB core library implementing confidential & scalable smart contracts for
//!   Bitcoin & Lightning ([`rgb-core`](https://github.com/rgb-org/rgb-core))
//! - [Universal invoicing library](https://github.com/LNP-BP/invoices)

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, missing_docs, warnings)]

pub extern crate lnpbp_bech32 as bech32;
pub extern crate lnpbp_chain as chain;
#[cfg(feature = "elgamal")]
pub extern crate lnpbp_elgamal as elgamal;
