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

use bitcoin::hashes::{sha256, sha256t, Hash, HashEngine};
use bitcoin::secp256k1::rand::{thread_rng, RngCore};
use bitcoin::{OutPoint, Txid};

use crate::bech32::ToBech32String;
use crate::client_side_validation::{
    commit_strategy, CommitConceal, CommitEncodeWithStrategy,
};
use crate::commit_verify::CommitVerify;
use crate::tagged_hash::TaggedHash;

/// Data required to generate or reveal the information about blinded
/// transaction outpoint
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    Default,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display("{txid}:{vout}!{blinding}")]
pub struct OutpointReveal {
    /// Blinding factor preventing rainbow table bruteforce attack based on
    /// the existing blockchain txid set
    pub blinding: u64,

    /// Txid that should be blinded
    pub txid: Txid,

    /// Tx output number that should be blinded
    pub vout: u32,
}

impl From<OutpointReveal> for OutPoint {
    #[inline]
    fn from(reveal: OutpointReveal) -> Self {
        OutPoint::new(reveal.txid, reveal.vout as u32)
    }
}

impl From<OutPoint> for OutpointReveal {
    fn from(outpoint: OutPoint) -> Self {
        Self {
            blinding: thread_rng().next_u64(),
            txid: outpoint.txid,
            vout: outpoint.vout as u32,
        }
    }
}

impl From<OutPoint> for OutpointHash {
    fn from(outpoint: OutPoint) -> Self {
        OutpointReveal::from(outpoint).commit_conceal()
    }
}

impl CommitConceal for OutpointReveal {
    type ConcealedCommitment = OutpointHash;

    #[inline]
    fn commit_conceal(&self) -> Self::ConcealedCommitment {
        self.outpoint_hash()
    }
}

impl OutpointReveal {
    #[inline]
    pub fn outpoint_hash(&self) -> OutpointHash {
        OutpointHash::commit(self)
    }
}

static MIDSTATE_OUTPOINT_HASH: [u8; 32] = [
    0xe8, 0xfb, 0x9e, 0x0d, 0xab, 0x40, 0x5c, 0x70, 0xe5, 0x34, 0xf4, 0x1f,
    0x58, 0x89, 0x19, 0x24, 0x55, 0x06, 0x72, 0x70, 0x9d, 0x52, 0x9f, 0xa5,
    0x84, 0xe2, 0x04, 0xd7, 0x94, 0x56, 0x30, 0x14,
];

/// Tag used for [`SchemaId`] hash type
pub struct OutpointHashTag;

impl sha256t::Tag for OutpointHashTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_OUTPOINT_HASH);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Blind version of transaction outpoint
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Display,
    From,
)]
#[wrapper(Debug, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull)]
#[display(OutpointHash::to_bech32_string)]
pub struct OutpointHash(
    #[cfg_attr(feature = "serde", serde(with = "crate::bech32"))]
    sha256t::Hash<OutpointHashTag>,
);

impl strict_encoding::Strategy for OutpointHash {
    type Strategy = strict_encoding::strategies::Wrapped;
}

impl CommitEncodeWithStrategy for OutpointHash {
    type Strategy = commit_strategy::UsingStrict;
}

impl CommitVerify<OutpointReveal> for OutpointHash {
    fn commit(reveal: &OutpointReveal) -> Self {
        let mut engine = sha256t::Hash::<OutpointHashTag>::engine();
        engine.input(&reveal.blinding.to_be_bytes()[..]);
        engine.input(&reveal.txid[..]);
        engine.input(&reveal.vout.to_be_bytes()[..]);
        let inner = sha256t::Hash::<OutpointHashTag>::from_engine(engine);
        OutpointHash::from_hash(inner)
    }
}

impl crate::bech32::Strategy for OutpointHash {
    const HRP: &'static str = "utxob";
    type Strategy = crate::bech32::strategies::UsingStrictEncoding;
}

impl crate::bech32::Strategy for sha256t::Hash<OutpointHashTag> {
    const HRP: &'static str = "utxob";
    type Strategy = crate::bech32::strategies::UsingStrictEncoding;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tagged_hash;
    use bitcoin::hashes::hex::FromHex;

    #[test]
    fn outpoint_hash_midstate() {
        let midstate = tagged_hash::Midstate::with(b"lnpbp:utxob");
        assert_eq!(**midstate, MIDSTATE_OUTPOINT_HASH);
    }

    #[test]
    fn outpoint_hash_bech32() {
        let outpoint_hash = OutpointReveal {
            blinding: 54683213134637,
            txid: Txid::from_hex("646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839").unwrap(),
            vout: 2,
        }.outpoint_hash();
        assert_eq!(
            "utxob1jy04k3kfv70n3gtgph7m4j5w6g09csyzdlnqkatsv6wgqsemlcxspewtfc",
            outpoint_hash.to_string()
        );
        assert_eq!(outpoint_hash.to_string(), outpoint_hash.to_bech32_string());
    }
}
