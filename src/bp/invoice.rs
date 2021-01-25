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

use bitcoin::hashes::sha256d;
use bitcoin::secp256k1::Signature;
use bitcoin::Address;
use miniscript::{descriptor::DescriptorPublicKey, Descriptor, Miniscript};
use url::Url;

use crate::bp::blind::OutpointHash;
use crate::bp::chain::AssetId;
use crate::bp::{Chain, HashLock, P2pNetworkId, Psbt, ScriptPubkeyFormat};
use crate::lnp::{tlv, Features};
use crate::secp256k1;

#[derive(Tlv)]
#[lnpbp_crate(crate)]
pub enum FieldType {
    #[tlv(type = 0x01)]
    Payers,
}

#[derive(Lnp)]
#[tlv_types(FieldType)]
#[lnpbp_crate(crate)]
pub struct Invoice {
    network: P2pNetworkId,

    /// List of beneficiary dests ordered in most desirable first order
    beneficiaries: Vec<Beneficiary>,

    /// Optional list of payers authored to pay
    #[tlv(type = FieldType::Payers)]
    payers: Vec<Payer>,
    quantity: Quantity,
    price: Option<AmountExt>,

    /// If the price of the asset provided by fiat provider URL goes below this
    /// limit the merchant will not accept the payment and it will become
    /// expired
    fiat_requirement: Option<Fiat>,
    merchant: Option<String>,
    asset: Option<AssetId>,
    purpose: Option<String>,
    details: Option<Details>,
    expiry: Option<i64>,

    #[tlv_unknown]
    unknown: Vec<tlv::Map>,
    signature: Option<Signature>,
}

#[non_exhaustive]
pub enum Beneficiary {
    /// Addresses are usefult when you do not like to leak public key
    /// information
    Address(Address),

    /// Ssed by protocols that work with existing UTXOs and can assign some
    /// client-validated data to them (like in RGB). We always hide the real
    /// UTXO behind the hashed version (using some salt)
    BlindUtxo(OutpointHash),

    /// Miniscript-based descriptors allowing custom derivation & key generation
    Descriptor(Descriptor<DescriptorPublicKey>),

    /// Full transaction template in PSBT format
    Psbt(Psbt),

    /// Lightning node receiving the payment. Not the same as lightning invoice
    /// since many of the invoice data now will be part of [`Invoice`] here.
    Lightning(LnAddress),

    /// Failback option for all future variants
    Other(Vec<u8>),
}

pub struct LnAddress {
    node_id: secp256k1::PublicKey,
    features: Features,
    hash_lock: HashLock,
    min_final_cltv_expiry: Option<u16>,
    path_hints: Vec<LnPathHint>,
}

/// Path hints for a lightning network payment, equal to the value of the `r`
/// key of the lightning BOLT-11 invoice
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md#tagged-fields>
pub struct LnPathHint {
    node_id: secp256k1::PublicKey,
    short_channel_id: ShortChannelId,
    fee_base_msat: u32,
    fee_proportional_millionths: u32,
    cltv_expiry_delta: u16,
}

pub enum AmountExt {
    Normal(u64),
    Milli(u64, u16),
}

pub struct Details {
    commitment: sha256d::Hash,
    source: Url,
}

pub struct Fiat {
    iso4217: [u8; 3],
    coins: u32,
    fractions: u8,
    price_provider: Url,
}

pub struct Quantity {
    min: Option<u32>,
    max: Option<u32>,
    default: u32,
}
