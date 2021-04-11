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

use std::collections::BTreeMap;

use bitcoin::hashes::{sha256d, Hash, HashEngine};
use bitcoin::secp256k1::rand::{thread_rng, Rng};
use bitcoin::util::uint::Uint256;
use client_side_validation::commit_verify::TryCommitVerify;
use wallet::Slice32;

/// Source data for creation of multi-message commitments according to LNPBP-4
/// procedure
pub type ProtocolId = Slice32;
pub type Commitment = sha256d::Hash;
pub type MessageMap = BTreeMap<ProtocolId, Commitment>;

#[derive(Copy, Clone, Error, Debug, Display)]
#[display(Debug)]
pub struct TooManyMessagesError;

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[display(Debug)]
pub struct MultimsgCommitmentItem {
    pub protocol: Option<ProtocolId>,
    pub commitment: Commitment,
}

impl MultimsgCommitmentItem {
    pub fn new(protocol: Option<ProtocolId>, commitment: Commitment) -> Self {
        Self {
            protocol,
            commitment,
        }
    }
}

/// Multimessage commitment data according to LNPBP-4 specification
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Display,
    Default,
    StrictEncode,
    StrictDecode,
)]
#[display(Debug)]
pub struct MultimsgCommitment {
    pub commitments: Vec<MultimsgCommitmentItem>,
    pub entropy: Option<u64>,
}

impl TryCommitVerify<MessageMap> for MultimsgCommitment {
    type Error = TooManyMessagesError;

    fn try_commit(multimsg: &MessageMap) -> Result<Self, TooManyMessagesError> {
        const SORT_LIMIT: usize = 2 << 16;

        let mut n = multimsg.len();
        // We use some minimum number of items, to increase privacy
        n = n.max(3);
        let ordered = loop {
            let mut ordered =
                BTreeMap::<usize, (ProtocolId, Commitment)>::new();
            // TODO #192: Modify arithmetics in LNPBP-4 spec
            //       <https://github.com/LNP-BP/LNPBPs/issues/19>
            if multimsg.into_iter().all(|(protocol, digest)| {
                let rem = Uint256::from_be_bytes(**protocol)
                    % Uint256::from_u64(n as u64)
                        .expect("Bitcoin U256 struct is broken");
                ordered
                    .insert(rem.low_u64() as usize, (*protocol, *digest))
                    .is_none()
            }) {
                break ordered;
            }
            n += 1;
            if n > SORT_LIMIT {
                // Memory allocation limit exceeded while trying to sort
                // multi-message commitment
                return Err(TooManyMessagesError);
            }
        };

        let entropy = {
            let mut rng = thread_rng();
            rng.gen::<u64>()
        };

        let mut commitments = Vec::<_>::with_capacity(n);
        for i in 0..n {
            match ordered.get(&i) {
                None => {
                    let mut engine = Commitment::engine();
                    for _ in 0..4 {
                        engine.input(&entropy.to_le_bytes());
                        engine.input(&i.to_le_bytes());
                    }
                    commitments.push(MultimsgCommitmentItem::new(
                        None,
                        Commitment::from_engine(engine),
                    ))
                }
                Some((contract_id, commitment)) => {
                    commitments.push(MultimsgCommitmentItem::new(
                        Some(*contract_id),
                        *commitment,
                    ))
                }
            }
        }

        Ok(Self {
            commitments,
            entropy: Some(entropy),
        })
    }
}
