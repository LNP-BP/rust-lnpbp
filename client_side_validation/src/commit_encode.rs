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

use std::io;

use bitcoin_hashes::{sha256, sha256d, Hash, HashEngine};

use super::commit_verify::{self, CommitVerify};

// TODO: Refactor all `CommitEncode`s into not requiring cloning
pub trait CommitEncode {
    fn commit_encode<E: io::Write>(&self, e: E) -> usize;
}

pub trait CommitEncodeWithStrategy {
    type Strategy;
}

/// Implemented after concept by Martin Habovštiak <martin.habovstiak@gmail.com>
pub mod commit_strategy {
    use super::*;
    use bitcoin_hashes::Hash;
    use std::collections::{BTreeMap, BTreeSet};

    // Defining strategies:
    pub struct UsingStrict;
    pub struct UsingConceal;
    pub struct UsingHash<H>(std::marker::PhantomData<H>)
    where
        H: Hash + strict_encoding::StrictEncode;
    pub struct Merklization;

    impl<T> CommitEncode for amplify::Holder<T, UsingStrict>
    where
        T: strict_encoding::StrictEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            self.as_inner().strict_encode(e).expect(
                "Strict encoding must not fail for types implementing \
                      ConsensusCommit via marker trait ConsensusCommitFromStrictEncoding",
            )
        }
    }

    impl<T> CommitEncode for amplify::Holder<T, UsingConceal>
    where
        T: CommitConceal,
        <T as CommitConceal>::Confidential: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            self.as_inner().conceal().commit_encode(e)
        }
    }

    impl<T, H> CommitEncode for amplify::Holder<T, UsingHash<H>>
    where
        H: Hash + strict_encoding::StrictEncode,
        T: strict_encoding::StrictEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            let mut engine = H::engine();
            engine
                .input(&strict_encoding::strict_serialize(self.as_inner()).expect(
                    "Strict encoding of hash strategy-based commitment data must not fail",
                ));
            let hash = H::from_engine(engine);
            hash.strict_encode(e).expect(
                "Strict encoding must not fail for types implementing \
                      ConsensusCommit via marker trait ConsensusCommitFromStrictEncoding",
            )
        }
    }

    impl<T> CommitEncode for amplify::Holder<T, Merklization>
    where
        T: IntoIterator + Clone,
        <T as IntoIterator>::Item: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            merklize(
                "",
                &self
                    .as_inner()
                    .clone()
                    .into_iter()
                    .map(|item| {
                        let mut encoder = io::Cursor::new(vec![]);
                        item.commit_encode(&mut encoder);
                        MerkleNode::hash(&encoder.into_inner())
                    })
                    .collect::<Vec<MerkleNode>>(),
                0,
            )
            .commit_encode(e)
        }
    }

    impl<K, V> CommitEncode for &(K, V)
    where
        K: CommitEncode,
        V: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
            self.0.commit_encode(&mut e) + self.1.commit_encode(&mut e)
        }
    }

    impl<K, V> CommitEncode for (K, V)
    where
        K: CommitEncode,
        V: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
            self.0.commit_encode(&mut e) + self.1.commit_encode(&mut e)
        }
    }

    impl<T> CommitEncode for T
    where
        T: CommitEncodeWithStrategy + Clone,
        amplify::Holder<T, <T as CommitEncodeWithStrategy>::Strategy>:
            CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            amplify::Holder::new(self.clone()).commit_encode(e)
        }
    }

    impl CommitEncodeWithStrategy for usize {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for u8 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for u16 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for u32 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for u64 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for i8 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for i16 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for i32 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for i64 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for String {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for &str {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for &[u8] {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for Vec<u8> {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for Vec<u16> {
        type Strategy = Merklization;
    }
    impl CommitEncodeWithStrategy for Vec<u32> {
        type Strategy = Merklization;
    }
    impl CommitEncodeWithStrategy for Vec<u64> {
        type Strategy = Merklization;
    }
    impl CommitEncodeWithStrategy for MerkleNode {
        type Strategy = UsingStrict;
    }

    #[cfg(feature = "grin_secp256k1zkp")]
    impl CommitEncodeWithStrategy for secp256k1zkp::pedersen::Commitment {
        type Strategy = commit_strategy::UsingStrict;
    }

    #[cfg(feature = "grin_secp256k1zkp")]
    impl CommitEncodeWithStrategy for secp256k1zkp::pedersen::RangeProof {
        type Strategy = commit_strategy::UsingHash<sha256::Hash>;
    }

    impl<K, V> CommitEncodeWithStrategy for BTreeMap<K, V> {
        type Strategy = Merklization;
    }
    impl<T> CommitEncodeWithStrategy for BTreeSet<T> {
        type Strategy = Merklization;
    }

    impl<T> CommitEncodeWithStrategy for &T
    where
        T: CommitEncodeWithStrategy,
    {
        type Strategy = T::Strategy;
    }
}

pub trait CommitConceal {
    type Confidential;
    fn conceal(&self) -> Self::Confidential;
}

pub trait ConsensusCommit: Sized + CommitEncode {
    type Commitment: commit_verify::CommitVerify<Vec<u8>>;

    #[inline]
    fn consensus_commit(self) -> Self::Commitment {
        let mut encoder = io::Cursor::new(vec![]);
        self.commit_encode(&mut encoder);
        Self::Commitment::commit(&encoder.into_inner())
    }

    #[inline]
    fn consensus_verify(self, commitment: &Self::Commitment) -> bool {
        let mut encoder = io::Cursor::new(vec![]);
        self.commit_encode(&mut encoder);
        commitment.verify(&encoder.into_inner())
    }
}

#[macro_export]
macro_rules! commit_encode_list {
    ( $encoder:ident; $($item:expr),+ ) => {
        {
            let mut len = 0usize;
            $(
                len += $item.commit_encode(&mut $encoder);
            )+
            len
        }
    }
}

hash_newtype!(
    MerkleNode,
    sha256d::Hash,
    32,
    doc = "A hash of a arbitrary Merkle tree branch or root"
);

impl strict_encoding::Strategy for MerkleNode {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}

/// Merklization procedure that uses tagged hashes with depth commitments
pub fn merklize(prefix: &str, data: &[MerkleNode], depth: u16) -> MerkleNode {
    let len = data.len();

    let mut engine = MerkleNode::engine();
    let tag = format!("{}:merkle:{}", prefix, depth);
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    match len {
        0 => {
            0u8.commit_encode(&mut engine);
            0u8.commit_encode(&mut engine);
        }
        1 => {
            data.first()
                .expect("We know that we have one element")
                .commit_encode(&mut engine);
            0u8.commit_encode(&mut engine);
        }
        2 => {
            data.first()
                .expect("We know that we have at least two elements")
                .commit_encode(&mut engine);
            data.last()
                .expect("We know that we have at least two elements")
                .commit_encode(&mut engine);
        }
        _ => {
            let div = len / 2;
            merklize(prefix, &data[0..div], depth + 1)
                .commit_encode(&mut engine);
            merklize(prefix, &data[div..], depth + 1)
                .commit_encode(&mut engine);
        }
    }
    MerkleNode::from_engine(engine)
}
