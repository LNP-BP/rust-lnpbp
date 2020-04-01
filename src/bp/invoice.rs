// LNP/BP Rust Library
// Written in 202 by
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

use bitcoin::{
    secp256k1,
    hash_types::*,
};
use miniscript::Miniscript;

use crate::bp::Satoshi;

#[derive(Copy, Clone, Debug, Display, PartialEq, Eq)]
#[display_from(Debug)]
pub struct Invoice {
    pub amount: Satoshi,
    pub receiver: Receiver,
}

#[derive(Copy, Clone, Debug, Display, PartialEq, Eq)]
#[display_from(Debug)]
#[non_exchaustive]
pub enum Receiver {
    P2PK(secp256k1::PublicKey),
    P2PKH(PubkeyHash),
    P2SH(ScriptHash),
    P2OR(Vec<u8>),
    P2WPKH(WPubkeyHash),
    P2WSH(WScriptHash),
    P2TR(secp256k1::PublicKey),
    Custom(Miniscript<bitcoin::PublicKey>),
}
