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

use amplify::Wrapper;
use bitcoin::hashes::{sha256, Hmac};
use bitcoin::{secp256k1, Transaction, TxOut};
use client_side_validation::commit_verify::EmbedCommitVerify;

use super::{
    Container, Error, Proof, ScriptEncodeData, ScriptEncodeMethod,
    TxoutCommitment, TxoutContainer,
};

/// Transaction contianer structure that can be used to commit to a message
/// The commitment process produces `TxCommitment` structure
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display(Debug)]
pub struct TxContainer {
    /// LNPBP2 Protocol Factor
    pub protocol_factor: u32,
    /// Transaction fee
    pub fee: u64,
    /// TxOut Container
    pub txout_container: TxoutContainer,
    /// Transaction
    pub tx: Transaction,
    /// Tweaking factor stored after [TxContainer::commit_verify] procedure
    pub tweaking_factor: Option<Hmac<sha256::Hash>>,
}

/// Transaction supplement structure used for constructing container
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display(Debug)]
pub struct TxSupplement {
    /// Protocol specific factor
    pub protocol_factor: u32,
    /// Transaction fee
    pub fee: u64,
    /// Single SHA256 hash of the protocol-specific tag
    pub tag: sha256::Hash,
}

impl TxContainer {
    /// Construct a container from data
    pub fn construct(
        protocol_factor: u32,
        protocol_tag: &sha256::Hash,
        fee: u64,
        tx: Transaction,
        pubkey: secp256k1::PublicKey,
        source: ScriptEncodeData,
        method: ScriptEncodeMethod,
    ) -> Self {
        let mut me = Self {
            tx,
            fee,
            protocol_factor,
            txout_container: TxoutContainer::construct(
                protocol_tag,
                0,
                pubkey,
                source,
                method,
            ),
            tweaking_factor: None,
        };
        me.txout_container.value = me.tx.output[me.vout()].value;
        me
    }

    /// Get the output index containing the commitment
    pub fn vout(&self) -> usize {
        let nouts = self.tx.output.len() as u16;
        let vout = ((self.fee + (self.protocol_factor as u64)) % (nouts as u64))
            as u16;
        vout as usize
    }
}

impl Container for TxContainer {
    type Supplement = TxSupplement;
    type Host = Transaction;

    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        host: &Self::Host,
    ) -> Result<Self, Error> {
        let mut me = Self {
            protocol_factor: supplement.protocol_factor,
            fee: supplement.fee,
            txout_container: TxoutContainer::reconstruct(
                proof,
                &supplement.tag,
                &TxOut::default(),
            )?,
            tx: host.clone(),
            tweaking_factor: None,
        };
        me.txout_container = TxoutContainer::reconstruct(
            proof,
            &supplement.tag,
            &host.output[me.vout()],
        )?;
        Ok(me)
    }

    fn deconstruct(self) -> (Proof, Self::Supplement) {
        (
            self.txout_container.clone().into_proof(),
            TxSupplement {
                protocol_factor: self.protocol_factor,
                fee: self.fee,
                tag: self.txout_container.script_container.tag,
            },
        )
    }

    fn to_proof(&self) -> Proof {
        self.txout_container.to_proof()
    }

    fn into_proof(self) -> Proof {
        self.txout_container.into_proof()
    }
}

/// [bitcoin::Transaction] containing LNPBP-3 commitment
#[derive(Wrapper, Clone, PartialEq, Eq, Hash, Debug, Display, From)]
#[display(Debug)]
pub struct TxCommitment(Transaction);

impl<MSG> EmbedCommitVerify<MSG> for TxCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = TxContainer;
    type Error = Error;

    fn embed_commit(
        container: &mut Self::Container,
        msg: &MSG,
    ) -> Result<Self, Self::Error> {
        let mut tx = container.tx.clone();

        let txout_commitment =
            TxoutCommitment::embed_commit(&mut container.txout_container, msg)?;
        tx.output[container.vout()] = txout_commitment.into_inner();

        container.tweaking_factor = container.txout_container.tweaking_factor;

        Ok(tx.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::dbc::{ScriptEncodeData, ScriptEncodeMethod, SpkContainer};
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::hex::FromHex;
    use std::str::FromStr;

    #[test]
    fn test_ability_to_commit() {
        let tx = deserialize(Vec::from_hex(
            "020000000001031cfbc8f54fbfa4a33a30068841371f80dbfe166211242213188428f437445c9100000000\
            6a47304402206fbcec8d2d2e740d824d3d36cc345b37d9f65d665a99f5bd5c9e8d42270a03a802201395963\
            2492332200c2908459547bf8dbf97c65ab1a28dec377d6f1d41d3d63e012103d7279dfb90ce17fe139ba60a\
            7c41ddf605b25e1c07a4ddcb9dfef4e7d6710f48feffffff476222484f5e35b3f0e43f65fc76e21d8be7818\
            dd6a989c160b1e5039b7835fc00000000171600140914414d3c94af70ac7e25407b0689e0baa10c77feffff\
            ffa83d954a62568bbc99cc644c62eb7383d7c2a2563041a0aeb891a6a4055895570000000017160014795d0\
            4cc2d4f31480d9a3710993fbd80d04301dffeffffff06fef72f000000000017a91476fd7035cd26f1a32a5a\
            b979e056713aac25796887a5000f00000000001976a914b8332d502a529571c6af4be66399cd33379071c58\
            8ac3fda0500000000001976a914fc1d692f8de10ae33295f090bea5fe49527d975c88ac522e1b0000000000\
            1976a914808406b54d1044c429ac54c0e189b0d8061667e088ac6eb68501000000001976a914dfab6085f3a\
            8fb3e6710206a5a959313c5618f4d88acbba20000000000001976a914eb3026552d7e3f3073457d0bee5d47\
            57de48160d88ac0002483045022100bee24b63212939d33d513e767bc79300051f7a0d433c3fcf1e0e3bf03\
            b9eb1d70220588dc45a9ce3a939103b4459ce47500b64e23ab118dfc03c9caa7d6bfc32b9c601210354fd80\
            328da0f9ae6eef2b3a81f74f9a6f66761fadf96f1d1d22b1fd6845876402483045022100e29c7e3a5efc10d\
            a6269e5fc20b6a1cb8beb92130cc52c67e46ef40aaa5cac5f0220644dd1b049727d991aece98a105563416e\
            10a5ac4221abac7d16931842d5c322012103960b87412d6e169f30e12106bdf70122aabb9eb61f455518322\
            a18b920a4dfa887d30700")
            .unwrap().as_slice()).unwrap();

        let mut container = TxContainer {
            tx,
            fee: 0,
            protocol_factor: 0,
            txout_container: TxoutContainer {
                value: 0,
                script_container: SpkContainer {
                    pubkey: secp256k1::PublicKey::from_str(
                        "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
                    )
                    .unwrap(),
                    source: ScriptEncodeData::SinglePubkey,
                    method: ScriptEncodeMethod::PublicKey,
                    tag: Default::default(),
                    tweaking_factor: None,
                },
                tweaking_factor: None,
            },
            tweaking_factor: None,
        };

        let msg = "message to commit to";

        let commitment =
            TxCommitment::embed_commit(&mut container, &msg).unwrap();
        assert_eq!(commitment.verify(&container, &msg).unwrap(), true);
    }
}
