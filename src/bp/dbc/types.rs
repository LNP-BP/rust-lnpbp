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

use bitcoin::secp256k1;

use super::{Error, ScriptEncodeData};

pub trait Container: Sized {
    type Supplement;
    type Host;

    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        host: &Self::Host,
    ) -> Result<Self, Error>;

    fn deconstruct(self) -> (Proof, Self::Supplement);

    fn to_proof(&self) -> Proof;
    fn into_proof(self) -> Proof;
}

#[derive(
    Clone, PartialEq, Eq, Hash, Debug, Display, StrictEncode, StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct Proof {
    pub pubkey: secp256k1::PublicKey,
    pub source: ScriptEncodeData,
}

#[cfg(test)]
impl Default for Proof {
    fn default() -> Self {
        use crate::SECP256K1;
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
