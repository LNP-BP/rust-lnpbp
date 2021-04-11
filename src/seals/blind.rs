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

use std::str::FromStr;

use bitcoin::hashes::{sha256, sha256d, sha256t, Hash, HashEngine};
use bitcoin::secp256k1::rand::{thread_rng, RngCore};
use bitcoin::{OutPoint, Txid};

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
#[display("{txid}:{vout}#{blinding:#x}")]
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

/// Errors happening during parsing string representation of different forms of
/// single-use-seals
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error, From,
)]
#[display(doc_comments)]
pub enum ParseError {
    /// full transaction id is required for the seal specification
    TxidRequired,

    /// blinding factor must be specified after `#`
    BlindingRequired,

    /// unable to parse blinding value; it must be a hexadecimal string
    /// starting with `0x`
    WrongBlinding,

    /// unable to parse transaction id value; it must be 64-character
    /// hexacecimal string
    WrongTxid,

    /// unable to parse transaction vout value; it must be a decimal unsigned
    /// integer
    WrongVout,

    /// wrong structure of seal string representation
    WrongStructure,

    /// blinding secret must be represented by a 64-bit hexadecimal value
    /// starting with `0x` and not with a decimal
    NonHexBlinding,

    /// wrong Bech32 representation of the blinded UTXO seal – {0}
    #[from]
    Bech32(crate::bech32::Error),
}

impl FromStr for OutpointReveal {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split(&[':', '#'][..]);
        match (split.next(), split.next(), split.next(), split.next()) {
            (Some("_"), ..) | (Some(""), ..) => Err(ParseError::TxidRequired),
            (Some(_), Some(_), None, ..) if s.contains(':') => {
                Err(ParseError::BlindingRequired)
            }
            (Some(_), Some(_), Some(blinding), None)
                if !blinding.starts_with("0x") =>
            {
                Err(ParseError::NonHexBlinding)
            }
            (Some(txid), Some(vout), Some(blinding), None) => {
                Ok(OutpointReveal {
                    blinding: u64::from_str_radix(
                        blinding.trim_start_matches("0x"),
                        16,
                    )
                    .map_err(|_| ParseError::WrongBlinding)?,
                    txid: txid.parse().map_err(|_| ParseError::WrongTxid)?,
                    vout: vout.parse().map_err(|_| ParseError::WrongVout)?,
                })
            }
            _ => Err(ParseError::WrongStructure),
        }
    }
}

/// Tag used for [`OutpointHash`] hash type
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
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(OutpointHash::from_bech32_str(s)?)
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

    #[test]
    fn outpoint_reveal_str() {
        let outpoint_reveal = OutpointReveal {
            blinding: 54683213134637,
            txid: Txid::from_hex("646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839").unwrap(),
            vout: 21,
        };

        let s = outpoint_reveal.to_string();
        assert_eq!(&s, "646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:21#0x31bbed7e7b2d");

        // round-trip
        assert_eq!(OutpointReveal::from_str(&s).unwrap(), outpoint_reveal);

        // wrong vout value
        assert_eq!(OutpointReveal::from_str(
            "646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:0x765#0x78ca95"
        ), Err(ParseError::WrongVout));
        assert_eq!(OutpointReveal::from_str(
            "646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:i9#0x78ca95"
        ), Err(ParseError::WrongVout));
        assert_eq!(OutpointReveal::from_str(
            "646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:-5#0x78ca95"
        ), Err(ParseError::WrongVout));

        // wrong blinding secret value
        assert_eq!(OutpointReveal::from_str(
            "646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#0x78cs"
        ), Err(ParseError::WrongBlinding));
        assert_eq!(OutpointReveal::from_str(
            "646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#78ca95"
        ), Err(ParseError::NonHexBlinding));
        assert_eq!(OutpointReveal::from_str(
            "646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#857"
        ), Err(ParseError::NonHexBlinding));
        assert_eq!(OutpointReveal::from_str(
            "646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#-5"
        ), Err(ParseError::NonHexBlinding));

        // wrong txid value
        assert_eq!(OutpointReveal::from_str(
            "646ca5c1062619e2a2d607719dfd820551fb773e4dc8c4ed67965a8d1fae839:5#0x78ca69"
        ), Err(ParseError::WrongTxid));
        assert_eq!(
            OutpointReveal::from_str("rvgbdg:5#0x78ca69"),
            Err(ParseError::WrongTxid)
        );
        assert_eq!(OutpointReveal::from_str(
            "10@646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:5#0x78ca69"
        ), Err(ParseError::WrongTxid));

        // wrong structure
        assert_eq!(OutpointReveal::from_str(
            "646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:1"
        ), Err(ParseError::BlindingRequired));
        assert_eq!(OutpointReveal::from_str(
            "646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839#0x78ca"
        ), Err(ParseError::WrongStructure));
        assert_eq!(OutpointReveal::from_str(
            "646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839"
        ), Err(ParseError::WrongStructure));
        assert_eq!(OutpointReveal::from_str(
            "646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839##0x78ca"
        ), Err(ParseError::WrongVout));
        assert_eq!(OutpointReveal::from_str(
            "646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839:#0x78ca95"
        ), Err(ParseError::WrongVout));
        assert_eq!(
            OutpointReveal::from_str("_:5#0x78ca"),
            Err(ParseError::TxidRequired)
        );
        assert_eq!(
            OutpointReveal::from_str(":5#0x78ca"),
            Err(ParseError::TxidRequired)
        );
    }
}
