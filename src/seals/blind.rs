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

use bitcoin::hashes::{sha256, sha256d, sha256t, Hash, HashEngine};
use bitcoin::secp256k1::rand::{thread_rng, RngCore};
use bitcoin::{OutPoint, Txid};
use std::str::FromStr;

use crate::bech32::{FromBech32Str, ToBech32String};
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

/// Tag used for [`SchemaId`] hash type
pub struct OutpointHashTag;

impl sha256t::Tag for OutpointHashTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        sha256::HashEngine::default()
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

impl FromStr for OutpointHash {
    type Err = crate::bech32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        OutpointHash::from_bech32_str(s)
    }
}

impl strict_encoding::Strategy for OutpointHash {
    type Strategy = strict_encoding::strategies::Wrapped;
}

impl CommitEncodeWithStrategy for OutpointHash {
    type Strategy = commit_strategy::UsingStrict;
}

impl CommitVerify<OutpointReveal> for OutpointHash {
    fn commit(reveal: &OutpointReveal) -> Self {
        let mut engine = sha256::Hash::engine();
        // NB: We are using different serialization byte order comparing to
        //     strict encode
        engine.input(&reveal.blinding.to_be_bytes()[..]);
        engine.input(&reveal.txid[..]);
        engine.input(&reveal.vout.to_be_bytes()[..]);

        let inner = sha256d::Hash::from_engine(engine);
        OutpointHash::from_hash(sha256t::Hash::<OutpointHashTag>::from_inner(
            inner.into_inner(),
        ))
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
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::hashes::sha256d;
    use bitcoin::hashes::sha256t::Tag;

    #[test]
    fn outpoint_hash_midstate() {
        assert_eq!(
            OutpointHashTag::engine().midstate(),
            sha256::HashEngine::default().midstate()
        );
    }

    #[test]
    fn outpoint_hash_is_sha256d() {
        let reveal = OutpointReveal {
            blinding: 54683213134637,
            txid: Txid::from_hex("646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839").unwrap(),
            vout: 2,
        };
        let outpoint_hash = reveal.outpoint_hash();
        let mut engine = sha256::HashEngine::default();
        engine.input(&reveal.blinding.to_be_bytes()[..]);
        engine.input(&reveal.txid[..]);
        engine.input(&reveal.vout.to_be_bytes()[..]);
        assert_eq!(**outpoint_hash, *sha256d::Hash::from_engine(engine))
    }

    #[test]
    fn outpoint_hash_bech32() {
        let outpoint_hash = OutpointReveal {
            blinding: 54683213134637,
            txid: Txid::from_hex("646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839").unwrap(),
            vout: 2,
        }.outpoint_hash();
        let bech32 =
            "utxob1ahrfaknwtv28c4yyhat5d9uel045ph797kxauj63p2gzykta9lkskn6smk";
        assert_eq!(bech32, outpoint_hash.to_string());
        assert_eq!(outpoint_hash.to_string(), outpoint_hash.to_bech32_string());
        let reconstructed = OutpointHash::from_str(bech32).unwrap();
        assert_eq!(reconstructed, outpoint_hash);
    }
}
