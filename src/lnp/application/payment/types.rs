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

use amplify::internet::InetSocketAddr;
use amplify::{DumbDefault, Wrapper};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::io;

use bitcoin::hashes::hex::{Error, FromHex};
use bitcoin::hashes::Hash;
use bitcoin::OutPoint;

use crate::bp::chain::AssetId;
use crate::bp::Slice32;
use crate::lnp::application::extension;
use crate::lnp::presentation::encoding::{strategies, Strategy};
use crate::paradigms::strict_encoding::{
    self, strict_deserialize, strict_serialize, Error as StrictError,
    StrictDecode, StrictEncode,
};
/// Shorthand for representing asset - amount pairs
pub type AssetsBalance = BTreeMap<AssetId, u64>;

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
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub enum ExtensionId {
    /// The channel itself
    Channel,

    Bolt3,
    Eltoo,
    Taproot,

    Htlc,
    Ptlc,
    ShutdownScript,
    AnchorOut,
    Dlc,
    Lightspeed,

    Bip96,
    Rgb,
}

impl Default for ExtensionId {
    fn default() -> Self {
        ExtensionId::Channel
    }
}

impl From<ExtensionId> for u16 {
    fn from(id: ExtensionId) -> Self {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(
            &strict_serialize(&id)
                .expect("Enum in-memory strict encoding can't fail"),
        );
        u16::from_be_bytes(buf)
    }
}

impl TryFrom<u16> for ExtensionId {
    type Error = strict_encoding::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        strict_deserialize(&value.to_be_bytes())
    }
}

impl extension::Nomenclature for ExtensionId {}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
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
    StrictEncode,
    StrictDecode,
)]
#[display(Debug)]
#[lnpbp_crate(crate)]
#[non_exhaustive]
#[repr(u8)]
pub enum Lifecycle {
    Initial,
    Proposed,                 // Sent or got `open_channel`
    Accepted,                 // Sent or got `accept_channel`
    Funding,                  // One party signed funding tx
    Signed,                   // Other peer signed funding tx
    Funded,                   // Funding tx is published but not mined
    Locked,                   // Funding tx mining confirmed by one peer
    Active,                   // Both peers confirmed lock, channel active
    Reestablishing,           // Reestablishing connectivity
    Shutdown,                 // Shutdown proposed but not yet accepted
    Closing { round: usize }, // Shutdown agreed, exchanging `closing_signed`
    Closed,                   // Cooperative closing
    Aborted,                  // Non-cooperative unilateral closing
}

impl Default for Lifecycle {
    fn default() -> Self {
        Lifecycle::Initial
    }
}

/// Lightning network channel Id
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper,
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
    From,
    StrictEncode,
    StrictDecode,
    LightningEncode,
    LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct ChannelId(
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    Slice32,
);

impl FromHex for ChannelId {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        Ok(Self(Slice32::from_byte_iter(iter)?))
    }
}

impl ChannelId {
    pub fn with(funding_outpoint: OutPoint) -> Self {
        let mut slice = funding_outpoint.txid.into_inner();
        let vout = funding_outpoint.vout.to_be_bytes();
        slice[30] ^= vout[0];
        slice[31] ^= vout[1];
        ChannelId::from_inner(Slice32::from_inner(slice))
    }
}

/// Lightning network temporary channel Id
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
    LightningEncode,
    LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct TempChannelId(
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    Slice32,
);

impl From<TempChannelId> for ChannelId {
    fn from(temp: TempChannelId) -> Self {
        Self(temp.into_inner())
    }
}

impl From<ChannelId> for TempChannelId {
    fn from(id: ChannelId) -> Self {
        Self(id.into_inner())
    }
}

impl FromHex for TempChannelId {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        Ok(Self(Slice32::from_byte_iter(iter)?))
    }
}

impl TempChannelId {
    #[cfg(feature = "keygen")]
    pub fn random() -> Self {
        TempChannelId::from_inner(Slice32::random())
    }
}

impl DumbDefault for TempChannelId {
    fn dumb_default() -> Self {
        Self(Default::default())
    }
}

#[derive(Wrapper, Clone, Debug, From, PartialEq, Eq)]
pub struct NodeColor([u8; 3]);

impl StrictEncode for NodeColor {
    fn strict_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, StrictError> {
        let len = e.write(self.as_inner())?;
        Ok(len)
    }
}

impl StrictDecode for NodeColor {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, StrictError> {
        let mut buf = [0u8; 3];
        d.read_exact(&mut buf)?;
        Ok(Self::from_inner(buf))
    }
}

impl Strategy for NodeColor {
    type Strategy = strategies::AsStrict;
}

#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
    LightningEncode,
    LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct Alias(
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    Slice32,
);

/// Lightning network short channel Id as per BOLT7
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
    From,
    Getters,
)]
#[display("short_channel_id({block_height}x{tx_index}x{output_index})")]
pub struct ShortChannelId {
    block_height: u32,
    tx_index: u32,
    output_index: u16,
}

impl ShortChannelId {
    pub fn new(
        block_height: u32,
        tx_index: u32,
        output_index: u16,
    ) -> Option<Self> {
        if block_height > 2 << 23 || tx_index > 2 << 23 {
            return None;
        } else {
            return Some(Self {
                block_height: block_height,
                tx_index: tx_index,
                output_index: output_index,
            });
        }
    }
}

impl StrictEncode for ShortChannelId {
    fn strict_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, StrictError> {
        let mut len = 0;

        // representing block height as 3 bytes
        let block_height: [u8; 3] = [
            (self.block_height >> 16 & 0xFF) as u8,
            (self.block_height >> 8 & 0xFF) as u8,
            (self.block_height & 0xFF) as u8,
        ];
        len += e.write(&block_height[..])?;

        // representing transaction index as 3 bytes
        let tx_index: [u8; 3] = [
            (self.tx_index >> 16 & 0xFF) as u8,
            (self.tx_index >> 8 & 0xFF) as u8,
            (self.tx_index & 0xFF) as u8,
        ];
        len += e.write(&tx_index[..])?;

        // represents output index as 2 bytes
        let output_index: [u8; 2] = [
            (self.output_index >> 8 & 0xFF) as u8,
            (self.output_index & 0xFF) as u8,
        ];
        len += e.write(&output_index[..])?;

        Ok(len)
    }
}

impl StrictDecode for ShortChannelId {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, StrictError> {
        // read the block height
        let mut block_height_bytes = [0u8; 3];
        d.read_exact(&mut block_height_bytes[..])?;

        let block_height = ((block_height_bytes[0] as u32) << 16)
            + ((block_height_bytes[1] as u32) << 8)
            + (block_height_bytes[2] as u32);

        // read the transaction index
        let mut transaction_index_bytes = [0u8; 3];
        d.read_exact(&mut transaction_index_bytes[..])?;

        let transaction_index = ((transaction_index_bytes[0] as u32) << 16)
            + ((transaction_index_bytes[1] as u32) << 8)
            + (transaction_index_bytes[2] as u32);

        // read the output index
        let mut output_index = [0u8; 2];
        d.read_exact(&mut output_index[..])?;

        let output_index =
            ((output_index[0] as u16) << 8) + (output_index[1] as u16);

        Ok(Self {
            block_height: block_height,
            tx_index: transaction_index,
            output_index: output_index,
        })
    }
}

impl Strategy for ShortChannelId {
    type Strategy = strategies::AsStrict;
}

#[derive(
    Wrapper,
    Clone,
    Debug,
    Display,
    From,
    PartialEq,
    Eq,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct AddressList(Vec<InetSocketAddr>);

impl Strategy for AddressList {
    type Strategy = strategies::AsStrict;
}
