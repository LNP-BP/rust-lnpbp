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
// TODO: Get rid of `bigint` dependency once `From<[u8; 16]>` and `Rem` will be impl for
//       `bitcoin::util::uint` types
use bigint::U256;

use bitcoin::{
    secp256k1::*,
    hashes::{sha256d, sha256t, Hash}
};

use super::committable::*;

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
    fn commit_to(msgs: &MSG) -> Self {
        let data: Vec<sha256t::Hash<TAG>> = msgs.into_iter().map(|item| item).collect();

        // <https://github.com/LNP-BP/lnpbps/blob/master/lnpbp-0004.md#commitment>
        // 1. Pick a 32-bytes of entropy from uniform entropy source (like the same which
        //    is used for generating private keys) and compute SHA256-tagged hash according to
        //    BIP-340 tagged hash procedure [4] with prefix `LNPBP4:random`.

        // `f767e5da583821cf6126cebd8c537e4ffe18139ab4d44a6fd33d5bb37beb5f0c` hex value
        const MIDSTATE_RANDOMNESS: [u8; 32] = [
            247, 103, 229, 218, 88, 56, 33, 207, 97, 38, 206, 189, 140, 83, 126, 79, 254, 24, 19,
            154, 180, 212, 74, 111, 211, 61, 91, 179, 123, 235, 95, 12
        ];
        tagged_hash!(RandomnessHash, RadomnessTag, MIDSTATE_RANDOMNESS,
                     doc="Hashed randomness according to LNPBP-4");

        let mut rng = rand::thread_rng();
        let random = SecretKey::new(&mut rng);
        let random_hash = RandomnessHash::hash(&random[..]);

        // 2. Generate a corresponding public key on Secp256k1 elliptic curve (R) and compute it's
        //    256-bit bitcoin hash (HASH256(R)).
        let r = SecretKey::from_slice(&random_hash[..])
            .expect("Probability of tis procedure failing is negligible");
        let rpubkey = PublicKey::from_secret_key(&Secp256k1::<All>::new(), &r);
        let rhash = sha256d::Hash::hash(&rpubkey.serialize());

        // 3. Finding bloom filter size
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

        // 4. Fill the buffer with messages
        let mut buf: Vec<u8> = vec![];
        for i in 1..=n {
            match data.iter().find(|hash| {
                U256::from(hash.into_inner()) % U256::from(i) == U256::zero()
            }) {
                Some(hash) => buf.extend_from_slice(&hash[..]),
                None => {
                    buf.extend_from_slice(&rhash[..])
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

