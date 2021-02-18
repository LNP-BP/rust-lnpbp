// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
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

#![recursion_limit = "256"]
// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    //missing_docs
)]

//! Primitives module defines core strict interfaces from informational LNPBP
//! standards specifying secure and robust practices for function calls
//! used in main LNP/BP development paradigms:
//! * Cryptographic commitments and verification
//! * Single-use seals
//! * Client-side validation
//! * Strict binary data serialization used by client-side validation
//!
//! The goal of this module is to maximally reduce the probability of errors and
//! mistakes within particular implementations of this paradigms by
//! standartizing typical workflow processes in a form of interfaces that
//! will be nearly impossible to use in the wrong form.

#[macro_use]
extern crate amplify_derive;
#[macro_use]
extern crate bitcoin_hashes;
#[cfg(test)]
#[macro_use]
extern crate strict_encoding;

#[macro_use]
mod commit_encode;
pub mod commit_verify;
mod digests;
pub mod single_use_seals;

pub use crate::commit_encode::{
    commit_strategy, merklize, CommitConceal, CommitEncode,
    CommitEncodeWithStrategy, ConsensusCommit, MerkleNode,
};
