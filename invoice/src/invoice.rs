// LNP/BP universal invoice library implementing LNPBP-38 standard
// Written in 2021 by
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

use chrono::NaiveDateTime;
use std::fmt::{self, Display, Formatter};
use url::Url;

use bitcoin::hashes::sha256d;
use bitcoin::secp256k1;
use bitcoin::secp256k1::Signature;
use bitcoin::Address;
use internet2::tlv;
use lnp::payment::ShortChannelId;
use lnp::Features;
use lnpbp::bech32::{self, ToBech32String};
use lnpbp::chain::AssetId;
use lnpbp::seals::OutpointHash;
use miniscript::{descriptor::DescriptorPublicKey, Descriptor};
use wallet::{HashLock, Psbt};

#[derive(
    Clone,
    Eq,
    PartialEq,
    Debug,
    Display,
    Default,
    StrictEncode,
    StrictDecode,
    LightningEncode,
    LightningDecode,
)]
#[display(Invoice::to_bech32_string)]
pub struct Invoice {
    /// List of beneficiary dests ordered in most desirable first order
    pub beneficiaries: Vec<Beneficiary>,

    pub expiry: Option<NaiveDateTime>, // Must be mapped to i64

    pub signature: Option<Signature>,

    /// AssetId can also be used to define blockchain. If it's empty it implies
    /// bitcoin mainnet
    #[tlv(type = 1)]
    pub asset: Option<AssetId>,

    #[tlv(type = 2)]
    pub quantity: Option<Quantity>,

    #[tlv(type = 3)]
    pub price: Option<AmountExt>,

    /// If the price of the asset provided by fiat provider URL goes below this
    /// limit the merchant will not accept the payment and it will become
    /// expired
    #[tlv(type = 5)]
    pub currency_requirement: Option<CurrencyData>,

    #[tlv(type = 7)]
    pub merchant: Option<String>,

    #[tlv(type = 9)]
    pub purpose: Option<String>,

    #[tlv(type = 11)]
    pub details: Option<Details>,

    #[tlv(unknown)]
    pub unknown: tlv::Map,
}

impl bech32::Strategy for Invoice {
    const HRP: &'static str = "i";

    type Strategy = bech32::strategies::UsingStrictEncoding;
}

#[derive(
    Clone,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
    LightningEncode,
    LightningDecode,
)]
#[display(inner)]
#[non_exhaustive]
pub enum Beneficiary {
    /// Addresses are useful when you do not like to leak public key
    /// information
    #[from]
    Address(Address),

    /// Used by protocols that work with existing UTXOs and can assign some
    /// client-validated data to them (like in RGB). We always hide the real
    /// UTXO behind the hashed version (using some salt)
    #[from]
    BlindUtxo(OutpointHash),

    /// Miniscript-based descriptors allowing custom derivation & key
    /// generation
    #[from]
    Descriptor(Descriptor<DescriptorPublicKey>),

    /// Full transaction template in PSBT format
    #[from]
    Psbt(Psbt),

    /// Lightning node receiving the payment. Not the same as lightning invoice
    /// since many of the invoice data now will be part of [`Invoice`] here.
    #[from]
    Lightning(LnAddress),

    /// Failback option for all future variants
    #[display(Vec::bech32_data_string)]
    Unknown(Vec<u8>),
}

#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
    LightningEncode,
    LightningDecode,
)]
#[display("{node_id}")]
pub struct LnAddress {
    pub node_id: secp256k1::PublicKey,
    pub features: Features,
    pub lock: HashLock, /* When PTLC will be available the same field will
                         * be re-used for them + the
                         * use will be indicated with a
                         * feature flag */
    pub min_final_cltv_expiry: Option<u16>,
    pub path_hints: Vec<LnPathHint>,
}

/// Path hints for a lightning network payment, equal to the value of the `r`
/// key of the lightning BOLT-11 invoice
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md#tagged-fields>
#[derive(
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
    LightningEncode,
    LightningDecode,
)]
#[display("{short_channel_id}@{node_id}")]
pub struct LnPathHint {
    pub node_id: secp256k1::PublicKey,
    pub short_channel_id: ShortChannelId,
    pub fee_base_msat: u32,
    pub fee_proportional_millionths: u32,
    pub cltv_expiry_delta: u16,
}

#[derive(
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
    LightningEncode,
    LightningDecode,
)]
pub enum AmountExt {
    #[from]
    #[display(inner)]
    Normal(u64),

    #[display("{0}.{1}")]
    Milli(u64, u16),
}

#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
    LightningEncode,
    LightningDecode,
)]
#[display("{source}")]
pub struct Details {
    pub commitment: sha256d::Hash,
    pub source: Url,
}

#[derive(
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
    LightningEncode,
    LightningDecode,
)]
#[display("{coins} {fractions} {iso4217}")]
pub struct CurrencyData {
    pub iso4217: [u8; 3],
    pub coins: u32,
    pub fractions: u8,
    pub price_provider: Url,
}

#[derive(
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    From,
    StrictEncode,
    StrictDecode,
    LightningEncode,
    LightningDecode,
)]
pub struct Quantity {
    pub min: u32, // We will default to zero
    pub max: Option<u32>,
    #[from]
    pub default: u32,
}

impl Default for Quantity {
    fn default() -> Self {
        Self {
            min: 0,
            max: None,
            default: 1,
        }
    }
}

impl Display for Quantity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} items", self.default)?;
        match (self.min, self.max) {
            (0, Some(max)) => write!(f, " (or any amount up to {})", max),
            (0, None) => {}
            (_, Some(max)) => write!(f, " (or from {} to {})", self.min, max),
            (_, None) => write!(f, " (or any amount above {})", self.min),
        }
    }
}
