// LNP/BP Rust Library
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

use std::collections::{BTreeMap, HashMap};
use std::io;

use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::util::uint::Uint256;
use bitcoin_hashes::{sha256, Hash};

use crate::bp::dbc::Proof;
//ScriptInfo, ScriptPubkeyComposition, ScriptPubkeyContainer, TxContainer, TxoutContainer,
use crate::commit_verify::CommitVerify;
use crate::lnpbp4::MultimsgCommitment;
use crate::rgb::{ContractId, TransitionId};
use crate::strict_encoding::{self, StrictDecode, StrictEncode};

#[derive(Clone, PartialEq, Eq, Debug, Display, From, Error)]
#[display_from(Debug)]
pub enum Error {
    NoRequiredOutputInformation(usize),
}

#[derive(Clone, Debug)]
pub struct Anchor {
    pub commitment: MultimsgCommitment,
    pub proof: Proof,
}

impl Anchor {
    pub fn new(
        transitions: HashMap<ContractId, TransitionId>,
        psbt: &mut Psbt,
        fee: u64,
    ) -> Result<Vec<Self>, Error> {
        let tx = &psbt.global.unsigned_tx;
        let num_outs = tx.output.len() as u64;

        let anchors = transitions
            .into_iter()
            .fold(
                HashMap::<usize, BTreeMap<sha256::Hash, sha256::Hash>>::new(),
                |mut data, (contract_id, t)| {
                    let id = Uint256::from_be_bytes(contract_id.into_inner());
                    let vout = id % Uint256::from_u64(num_outs).unwrap();
                    let vout = vout.low_u64() as usize;
                    data.entry(vout).or_insert(BTreeMap::default()).insert(
                        sha256::Hash::from_inner(contract_id.into_inner()),
                        sha256::Hash::from_inner(t.into_inner()),
                    );
                    data
                },
            )
            .into_iter()
            .try_for_each(|(vout, multimsg)| {
                let commitment = MultimsgCommitment::commit(&multimsg);
                let out = psbt
                    .outputs
                    .get(vout)
                    .ok_or(Error::NoRequiredOutputInformation(vout))?;

                /*
                let container = TxContainer {
                    tx: tx.clone(),
                    fee,
                    protocol_factor: 0,
                    txout_container: TxoutContainer {
                        value: tx.output[vout].value,
                        script_container: ScriptPubkeyContainer {
                            pubkey: secp256k1::PublicKey::from_str(
                                "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
                            )
                                .unwrap(),
                            script_info: ScriptInfo::None,
                            scriptpubkey_composition: ScriptPubkeyComposition::PublicKey,
                            tag: Default::default(),
                        },
                    },
                };
                 */

                Ok(())
            })?;

        Ok(vec![])
    }
}

impl StrictEncode for Anchor {
    fn strict_encode<E: io::Write>(&self, _: E) -> Result<usize, strict_encoding::Error> {
        unimplemented!()
    }
}

impl StrictDecode for Anchor {
    fn strict_decode<D: io::Read>(_: D) -> Result<Self, strict_encoding::Error> {
        unimplemented!()
    }
}
