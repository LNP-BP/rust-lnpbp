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
use std::iter::FromIterator;

use bitcoin_hashes::{sha256, sha256d, Hash, HashEngine};

use super::commit_verify::{self, CommitVerify};

pub trait CommitEncode {
    fn commit_encode<E: io::Write>(&self, e: E) -> usize;
    fn commit_serialize(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        self.commit_encode(&mut vec);
        vec
    }
}

pub trait CommitEncodeWithStrategy {
    type Strategy;
}

/// Implemented after concept by Martin Habovštiak <martin.habovstiak@gmail.com>
pub mod commit_strategy {
    use super::*;
    use bitcoin_hashes::Hash;

    // Defining strategies:
    pub struct UsingStrict;
    pub struct UsingConceal;
    pub struct UsingHash<H>(std::marker::PhantomData<H>)
    where
        H: Hash + strict_encoding::StrictEncode;

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
        <T as CommitConceal>::ConcealedCommitment: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            self.as_inner().commit_conceal().commit_encode(e)
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

    impl<K, V> CommitEncode for (K, V)
    where
        K: CommitEncode,
        V: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
            self.0.commit_encode(&mut e) + self.1.commit_encode(&mut e)
        }
    }

    impl<A, B, C> CommitEncode for (A, B, C)
    where
        A: CommitEncode,
        B: CommitEncode,
        C: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
            self.0.commit_encode(&mut e)
                + self.1.commit_encode(&mut e)
                + self.2.commit_encode(&mut e)
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

    impl<T> CommitEncodeWithStrategy for &T
    where
        T: CommitEncodeWithStrategy,
    {
        type Strategy = T::Strategy;
    }
}

pub trait CommitConceal {
    type ConcealedCommitment;
    fn commit_conceal(&self) -> Self::ConcealedCommitment;
}

pub trait ConsensusCommit: Sized + CommitEncode {
    type Commitment: commit_verify::CommitVerify<Vec<u8>>;

    #[inline]
    fn consensus_commit(&self) -> Self::Commitment {
        let mut encoder = io::Cursor::new(vec![]);
        self.commit_encode(&mut encoder);
        Self::Commitment::commit(&encoder.into_inner())
    }

    #[inline]
    fn consensus_verify(&self, commitment: &Self::Commitment) -> bool {
        let mut encoder = io::Cursor::new(vec![]);
        self.commit_encode(&mut encoder);
        commitment.verify(&encoder.into_inner())
    }
}

pub trait ConsensusMerkleCommit:
    ConsensusCommit<Commitment = MerkleNode>
{
    const MERKLE_NODE_TAG: &'static str;
}

impl<A, B> ConsensusCommit for (A, B)
where
    A: CommitEncode,
    B: CommitEncode,
{
    type Commitment = MerkleNode;
}

impl<A, B, C> ConsensusCommit for (A, B, C)
where
    A: CommitEncode,
    B: CommitEncode,
    C: CommitEncode,
{
    type Commitment = MerkleNode;
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

impl<MSG> CommitVerify<MSG> for MerkleNode
where
    MSG: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &MSG) -> MerkleNode {
        MerkleNode::hash(msg.as_ref())
    }
}

/// Merklization procedure that uses tagged hashes with depth commitments
pub fn merklize(prefix: &str, data: &[MerkleNode], depth: u16) -> MerkleNode {
    let len = data.len();

    let mut engine = MerkleNode::engine();
    // Computing tagged hash as per BIP-340
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct MerkleSource<T>(pub Vec<T>);

impl<L, I> From<I> for MerkleSource<L>
where
    I: IntoIterator<Item = L>,
    L: CommitEncode,
{
    fn from(collection: I) -> Self {
        Self(collection.into_iter().collect())
    }
}

impl<L> FromIterator<L> for MerkleSource<L>
where
    L: CommitEncode,
{
    fn from_iter<T: IntoIterator<Item = L>>(iter: T) -> Self {
        iter.into_iter().collect::<Vec<_>>().into()
    }
}

impl<L> CommitEncode for MerkleSource<L>
where
    L: ConsensusMerkleCommit,
{
    fn commit_encode<E: io::Write>(&self, e: E) -> usize {
        let leafs = &self
            .0
            .iter()
            .map(L::consensus_commit)
            .collect::<Vec<MerkleNode>>();
        merklize(L::MERKLE_NODE_TAG, leafs, 0).commit_encode(e)
    }
}

impl<L> ConsensusCommit for MerkleSource<L>
where
    L: ConsensusMerkleCommit + CommitEncode,
{
    type Commitment = MerkleNode;

    #[inline]
    fn consensus_commit(&self) -> Self::Commitment {
        MerkleNode::from_slice(&self.commit_serialize())
            .expect("MerkleSource::commit_serialize must produce MerkleNode")
    }

    #[inline]
    fn consensus_verify(&self, commitment: &Self::Commitment) -> bool {
        self.consensus_commit() == *commitment
    }
}

pub trait ToMerkleSource {
    type Leaf: ConsensusMerkleCommit;
    fn to_merkle_source(&self) -> MerkleSource<Self::Leaf>;
}

#[cfg(test)]
mod test {
    use super::*;
    use amplify::{bmap, s};
    use bitcoin_hashes::hex::ToHex;
    use std::collections::BTreeMap;
    use strict_encoding::StrictEncode;

    #[test]
    fn collections() {
        // First, we define a data type
        #[derive(
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Debug,
            StrictEncode,
            StrictDecode,
        )]
        struct Item(pub String);
        // Next, we say that it should be concealed using some function
        // (double SHA256 hash in this case)
        impl CommitConceal for Item {
            type ConcealedCommitment = sha256d::Hash;
            fn commit_conceal(&self) -> Self::ConcealedCommitment {
                sha256d::Hash::hash(self.0.as_bytes())
            }
        }
        // Next, we need to specify how the concealed data should be
        // commit-encoded: this time we strict-serialize the hash
        impl CommitEncodeWithStrategy for sha256d::Hash {
            type Strategy = commit_strategy::UsingStrict;
        }
        // Now, we define commitment encoding for our concealable type: it
        // should conceal the data
        impl CommitEncodeWithStrategy for Item {
            type Strategy = commit_strategy::UsingConceal;
        }
        // Now, we need to say that consensus commit procedure should produce
        // a final commitment from commit-encoded data (equal to the
        // strict encoding of the conceal result) using `CommitVerify` type.
        // Here, we use another round of hashing, producing merkle node hash
        // from the concealed data.
        impl ConsensusCommit for Item {
            type Commitment = MerkleNode;
        }
        // Next, we need to provide merkle node tags for each type of the tree
        impl ConsensusMerkleCommit for Item {
            const MERKLE_NODE_TAG: &'static str = "item";
        }
        impl ConsensusMerkleCommit for (usize, Item) {
            const MERKLE_NODE_TAG: &'static str = "usize->item";
        }

        impl ToMerkleSource for BTreeMap<usize, Item> {
            type Leaf = (usize, Item);
            fn to_merkle_source(&self) -> MerkleSource<Self::Leaf> {
                self.iter().map(|(k, v)| (*k, v.clone())).collect()
            }
        }

        let item = Item(s!("Some text"));
        assert_eq!(&b"\x09\x00Some text"[..], item.strict_serialize().unwrap());
        assert_eq!(
            "6680bbec0d05d3eaac9c8b658c40f28d2f0cb0f245c7b1cabf5a61c35bd03d8e",
            item.commit_serialize().to_hex()
        );
        assert_eq!(
            "df08dc157bbd5676d5aeb1b437fa0cded8d3e21699adee2fcbbadef131a9e895",
            item.consensus_commit().to_hex()
        );
        assert_ne!(item.commit_serialize(), item.strict_serialize().unwrap());
        assert_eq!(
            MerkleNode::hash(&item.commit_serialize()),
            item.consensus_commit()
        );

        let original = bmap! {
            0usize => Item(s!("My first case")),
            1usize => Item(s!("My second case with a very long string")),
            3usize => Item(s!("My third case to make the Merkle tree two layered"))
        };
        let collection = original.to_merkle_source();
        assert_eq!(
            &b"\x03\x00\
             \x00\x00\
             \x0d\x00\
             My first case\
             \x01\x00\
             \x26\x00\
             My second case with a very long string\
             \x03\x00\
             \x31\x00\
             My third case to make the Merkle tree two layered"[..],
            original.strict_serialize().unwrap()
        );
        assert_eq!(
            "b497ced8b6431336e4c66ffd56a504633c828ea3ec0c0495a31e9a14cb066406",
            collection.commit_serialize().to_hex()
        );
        assert_eq!(
            "066406cb149a1ea395040ceca38e823c6304a556fd6fc6e4361343b6d8ce97b4",
            collection.consensus_commit().to_hex()
        );
        assert_ne!(
            collection.commit_serialize(),
            original.strict_serialize().unwrap()
        );
        assert_eq!(
            MerkleNode::from_slice(&collection.commit_serialize()).unwrap(),
            collection.consensus_commit()
        );

        let original = vec![
            Item(s!("My first case")),
            Item(s!("My second case with a very long string")),
            Item(s!("My third case to make the Merkle tree two layered")),
        ];
        let vec: MerkleSource<Item> = original.clone().into();
        assert_eq!(
            &b"\x03\x00\
             \x0d\x00\
             My first case\
             \x26\x00\
             My second case with a very long string\
             \x31\x00\
             My third case to make the Merkle tree two layered"[..],
            original.strict_serialize().unwrap()
        );
        assert_eq!(
            "8a8ebc499d146b0ab551e0ff985cf8166dc05f20f04b0f5991c4b9242dbde205",
            vec.commit_serialize().to_hex()
        );
        assert_eq!(
            "05e2bd2d24b9c491590f4bf0205fc06d16f85c98ffe051b50a6b149d49bc8e8a",
            vec.consensus_commit().to_hex()
        );
        assert_ne!(
            vec.commit_serialize(),
            original.strict_serialize().unwrap()
        );
        assert_eq!(
            MerkleNode::from_slice(&vec.commit_serialize()).unwrap(),
            vec.consensus_commit()
        );
        assert_ne!(vec.consensus_commit(), collection.consensus_commit());
    }
}
