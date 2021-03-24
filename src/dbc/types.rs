// LNP/BP Rust Library
// Written in 2019 by
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

use amplify::DumbDefault;
use bitcoin::secp256k1;

use super::{Error, ScriptEncodeData};

/// Container structure to be used for creating commitment to a message
pub trait Container: Sized {
    /// Supplement data used while commitment
    type Supplement;
    /// Host structure where committed data will be stored
    type Host;

    /// Reconstruct a container from [Proof], [Supplement] and [Host]
    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        host: &Self::Host,
    ) -> Result<Self, Error>;

    /// Deconstruct a container into [Proof] and [Supplement]
    fn deconstruct(self) -> (Proof, Self::Supplement);

    /// Produce the [Proof] from [Container]
    fn to_proof(&self) -> Proof;
    /// Produce the [Proof] from [Container] while consuming [Self]
    fn into_proof(self) -> Proof;
}

#[derive(
    Clone, PartialEq, Eq, Hash, Debug, Display, StrictEncode, StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display("proof({pubkey}, {source}")]
/// The proof of commitment.
pub struct Proof {
    /// Public Key containing the tweak
    pub pubkey: secp256k1::PublicKey,
    /// Lockscript to be satisfied by spending Tx
    pub source: ScriptEncodeData,
}

impl DumbDefault for Proof {
    fn dumb_default() -> Self {
        use wallet::SECP256K1;
        Proof {
            pubkey: secp256k1::PublicKey::from_secret_key(
                &SECP256K1,
                &secp256k1::key::ONE_KEY,
            ),
            source: Default::default(),
        }
    }
}

impl From<secp256k1::PublicKey> for Proof {
    fn from(pubkey: secp256k1::PublicKey) -> Self {
        Self {
            pubkey,
            source: ScriptEncodeData::SinglePubkey,
        }
    }
}
