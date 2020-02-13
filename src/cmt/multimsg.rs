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

use std::collections::HashSet;
use rand::Rng;
// TODO: Get rid of `bigint` dependency once `From<[u8; 16]>` and `Rem` will be impl for
//       `bitcoin::util::uint` types
use bigint::U256;

use bitcoin::hashes::{sha256d, sha256t, Hash};

use super::committable::*;
use crate::AsSlice;


//hash_newtype!(MultimsgCommitment, sha256d::Hash, 32, doc="LNPBP-4 multimessage commitment");
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MultimsgCommitment(sha256d::Hash);


impl<MSG, TAG> CommitmentVerify<MSG> for MultimsgCommitment where
    MSG: Committable<Self> + IntoIterator<Item=sha256t::Hash<TAG>> + Copy,
    TAG: sha256t::Tag
{
    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool {
        <Self as StandaloneCommitment<MSG>>::reveal_verify(&self, &msg)
    }
}

impl<MSG, TAG> StandaloneCommitment<MSG> for MultimsgCommitment where
    MSG: Committable<Self> + IntoIterator<Item=sha256t::Hash<TAG>> + Copy,
    TAG: sha256t::Tag
{
    #[inline]
    fn commit_to(msgs: &MSG) -> Self {
        let data: Vec<sha256d::Hash> = msgs.into_iter().map(|msg| {
            let digest = sha256d::Hash::hash(msg.as_slice());
            digest
        }).collect();

        // Finding bloom filter size
        let mut n = data.len();
        loop {
            let mut uniq = HashSet::new();
            if data.iter().into_iter().all(|hash| {
                let u = U256::from(hash.into_inner());
                uniq.insert(u % U256::from(n))
            }) {
                break;
            }
            n += 1;
        }

        let mut buf: Vec<u8> = vec![];
        let mut rng = rand::thread_rng();
        for i in 1..=n {
            match data.iter().find(|hash| {
                U256::from(hash.into_inner()) % U256::from(i) == U256::zero()
            }) {
                Some(hash) => buf.extend_from_slice(&hash[..]),
                None => {
                    let r = rng.gen::<u64>().to_le_bytes();
                    buf.extend_from_slice(&sha256d::Hash::hash(&r)[..])
                },
            }
        }
        let commitment = sha256d::Hash::hash(&buf[..]);

        unimplemented!()
    }
}


impl<MSG, TAG> Verifiable<MultimsgCommitment> for MSG where
    MSG: IntoIterator<Item=sha256t::Hash<TAG>> + Copy,
    TAG: sha256t::Tag
{ }

impl<MSG, TAG> Committable<MultimsgCommitment> for MSG where
    MSG: IntoIterator<Item=sha256t::Hash<TAG>> + Copy,
    TAG: sha256t::Tag
{ }

